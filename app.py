import base64
import hashlib
import json
import os
import time
from datetime import datetime
from copy import deepcopy
from pathlib import Path
import streamlit as st
import plotly.graph_objects as go
from core import read_sbom, repository_input, score, sidecar, CONTROLS, BASELINE
from evidence import (collect, collect_inventory, collection_status, unknown_evidence, synthetic,
                      new_collection, step_collection, stop_collection, resume_collection, collection_counts, inventory_signature)
from research import run_batch
from reporting import pdf_report, matrix_figure
from mission import initialize as initialize_mission, assign as assign_mission, undo as undo_mission
from control_plan import prepare_draft, invalidate_draft, selected_plan, priorities, priority_value, justification, selectable
from tutorial import coach, start as start_tutorial, active as tutorial_active
from connections import check_credential, connection_key
from local_llm import PROVIDERS, local_base_url, list_models, preferred_model, control_context, context_fingerprint, generate_controls
from mapping import package_ref, purl_type, candidate_options, apply_candidates, auto_map_all

st.set_page_config(page_title='HEPHAESTUS', page_icon='assets/favicon.svg', layout='wide', initial_sidebar_state='expanded')
network_image=base64.b64encode(Path('assets/network.png').read_bytes()).decode()
st.markdown("<style>" + Path('assets/theme.css').read_text() + ":root{--network-image:url(data:image/png;base64,"+network_image+");}</style>", unsafe_allow_html=True)
if 'view' not in st.session_state: st.session_state.view='assessment'
def go_assessment(): st.session_state.view='assessment'
def go_readme():
    stop_collection(st.session_state.get('collection_job'))
    st.session_state.view='readme'
def request_assessment_collection(repositories):
    st.session_state.evidence_mode='Live GitHub'
    st.session_state.collect_assessment_requested=True
    st.session_state.assessment_requested_repos=list(repositories)
    st.session_state.retry_assessment_requested=False
def request_assessment_retry(repositories):
    request_assessment_collection(repositories)
    st.session_state.retry_assessment_requested=True
def enable_live_mode():
    st.session_state.evidence_mode='Live GitHub'
def request_research(repositories,retry=False):
    enable_live_mode()
    st.session_state.research_requested={'repositories':list(repositories),'retry':retry}
def display_score(value): return 'Unknown' if value is None else f'{value:.1f}'
def credential_feedback(service, secret, project=''):
    label='GitHub token' if service=='github' else 'Tavily API key'
    key=connection_key(service,secret,project)
    previous=st.session_state.get(service+'_credential_check',{})
    recheck=st.button('Recheck '+label,key='recheck_'+service,disabled=not secret)
    if secret and (recheck or previous.get('key')!=key):
        with st.spinner('Checking '+label+'…'):
            previous={'key':key,**check_credential(service,secret,project)}
        st.session_state[service+'_credential_check']=previous
    if not secret:
        st.session_state.pop(service+'_credential_check',None)
        st.caption('No token supplied; public GitHub requests can still work.' if service=='github' else 'No key supplied; contributor web research is unavailable.')
    else:
        show=st.success if previous.get('state')=='accepted' else st.error if previous.get('state')=='rejected' else st.warning
        show(previous.get('message','Not checked.'))
        if previous.get('checked_at'): st.caption('Checked: '+previous['checked_at'])

if 'sidebar_open' not in st.session_state:
    st.session_state.sidebar_open=True
def toggle_sidebar():
    st.session_state.sidebar_open=not st.session_state.sidebar_open
st.button('Hide sidebar' if st.session_state.sidebar_open else 'Show sidebar', key='sidebar_toggle', on_click=toggle_sidebar)
if not st.session_state.sidebar_open:
    st.markdown('<style>[data-testid="stSidebar"]{display:none!important;}</style>',unsafe_allow_html=True)
if st.session_state.view!='assessment':
    st.button('Back to assessment',key='back_assessment',on_click=go_assessment)
st.markdown('<div class="brand"><img src="data:image/svg+xml;base64,'+base64.b64encode(Path('assets/favicon.svg').read_bytes()).decode()+'" alt="Anvil"/><h1>HEPHAESTUS</h1></div>',unsafe_allow_html=True)
with st.sidebar:
    st.subheader('Inventory', help='Choose an evidence source and import a CycloneDX, SPDX 2.x JSON, or SPDX 3 JSON-LD inventory.')
    coach('inventory')
    mode=st.radio('Evidence mode',['Offline scenario','Live GitHub'],key='evidence_mode', help='Offline evidence is synthetic for bundled samples only. Uploaded SBOMs start without evidence. Collect all GitHub evidence switches to Live GitHub and collects observations after you click; upload alone does not start requests.')
    upload=st.file_uploader('Import an SBOM',type=['json','jsonld'], help='CycloneDX, SPDX 2.x JSON, or SPDX 3 JSON-LD, up to 10 MB. Repository links come from the file and require verification.')
    upload_status=st.empty()
    sample=st.selectbox('Sample inventory',['CycloneDX','SPDX','SPDX 3'], help='Bundled example inventories. Offline scenario values are synthetic, not findings about the listed projects.')
    st.subheader('Connections')
    st.caption('Press Enter or leave a credential field to check it. Checks do not start searches. Recheck retries a check without changing the value.')
    token=st.text_input('GitHub token (optional)',type='password',value=os.getenv('GITHUB_TOKEN',''),key='github_token', help=(
        'GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token. '
        '[Create a token](https://github.com/settings/personal-access-tokens/new).\n\n'
        'Give it a name and expiration. For public repository observations, choose Public repositories (read-only); no write permissions are needed. '
        'Reading branch protection settings may additionally require selected-repository access and Administration: read, subject to your existing access.\n\n'
        'Copy the generated token into this field (not your GitHub password). It stays in this session and is never exported. '
        'A token can increase API limits; public requests can also work without one.'
    ))
    credential_feedback('github',token)
    use_scorecard=st.checkbox('Include OpenSSF Scorecard',False, help='Fetch optional repository security-check context. Scorecard results are shown separately and do not affect this model.')
    tavily_key=st.text_input('Tavily API key (optional)',type='password',value=os.getenv('TAVILY_API_KEY',''),key='tavily_api_key', help='Checked using the usage endpoint without running searches. Enables contributor web-source research. The key stays in session and is never exported. Queries send public GitHub names, handles, and repository identifiers to Tavily only when you run research.')
    project_id=st.text_input('Tavily project ID (optional)',value=os.getenv('TAVILY_PROJECT_ID',''),key='tavily_project_id',help='Optional usage attribution for Tavily requests. Changing it rechecks the key and project combination. Not included in exported reports.')
    credential_feedback('tavily',tavily_key,project_id)
    coach('connections')
    with st.expander('Local LLM connection'):
        provider_default=os.getenv('LOCAL_LLM_PROVIDER','Ollama')
        llm_provider=st.selectbox('Local API type',PROVIDERS,index=PROVIDERS.index(provider_default) if provider_default in PROVIDERS else 0,key='local_llm_provider',help='Ollama uses its native chat API. OpenAI-compatible uses /v1/chat/completions. OpenAI-compatible text uses /v1/completions for servers or models with a text-completion API. Model names are unrestricted.')
        default_endpoint='http://127.0.0.1:11434' if llm_provider=='Ollama' else 'http://127.0.0.1:1234/v1'
        llm_endpoint=st.text_input('Local server URL',value=os.getenv('LOCAL_LLM_URL',default_endpoint),key='local_llm_url_'+llm_provider,help='Ollama normally uses http://127.0.0.1:11434. LM Studio normally uses http://127.0.0.1:1234/v1. The server must run on the same machine as HEPHAESTUS; only loopback URLs are accepted.')
        llm_key=st.text_input('Local model API key (optional)',type='password',value=os.getenv('LOCAL_LLM_API_KEY',''),key='local_llm_api_key',help='Only for a local server that requires authentication. Sent only to the configured loopback endpoint. Never included in the prompt or report.')
        manual_model=st.text_input('Model ID override (optional)',value=os.getenv('LOCAL_LLM_MODEL',''),key='local_model_override',help='Enter any model identifier your server accepts. Overrides the model list and permits generation when a server does not implement model discovery. There is no required model family or size.')
        llm_structured=st.checkbox('Request structured JSON',value=True,key='local_llm_structured',help='Ollama can enforce JSON output. Turn this off for models that do not support it. Other APIs receive a formatting instruction only. Non-structured responses are retained as plain-text drafts.')
        llm_timeout=st.number_input('Generation timeout (seconds)',min_value=30,max_value=300,value=120,step=30,help='Large models may need more time to load and respond. Connection checks have a separate short timeout.')
        llm_config=connection_key(llm_provider,llm_endpoint,llm_key)
        if st.button('Connect local model',key='connect_local_llm'):
            with st.spinner('Checking local server and listing models…'):
                try:
                    models=list_models(llm_provider,llm_endpoint,llm_key)
                    st.session_state.local_llm_connection={'key':llm_config,'models':models,'state':'connected'}
                except ValueError as exc:
                    st.session_state.local_llm_connection={'key':llm_config,'models':[],'state':'failed','message':str(exc)}
        llm_connection=st.session_state.get('local_llm_connection',{})
        llm_ready=llm_connection.get('key')==llm_config and llm_connection.get('state')=='connected'
        llm_models=llm_connection.get('models',[]) if llm_ready else []
        llm_model=''
        if llm_ready:
            st.success('Local server accepted the connection'+(' and API key.' if llm_key else '.'))
            if llm_models:
                preferred=preferred_model(llm_models,os.getenv('LOCAL_LLM_MODEL',''))
                llm_model=st.selectbox('Local model',llm_models,index=llm_models.index(preferred),key='local_model_'+llm_config,help='Use the identifier returned by your server, such as gpt-oss:20b. Connecting lists models; it does not generate controls.')
            else: st.warning('Server connected, but no models are available. Install or load a model in your local runner, then reconnect.')
        elif llm_connection.get('key')==llm_config and llm_connection.get('state')=='failed': st.error(llm_connection['message'])
        else: st.caption('Not connected. Start Ollama or LM Studio, then connect to list available models.')
        if manual_model.strip():
            llm_model=manual_model.strip()
            st.caption('Manual model ID selected. Generation will verify this model endpoint even if model discovery is unavailable.')
        try:
            local_base_url(llm_endpoint,llm_provider)
            llm_can_generate=bool(llm_model)
        except ValueError:
            llm_can_generate=False
        st.caption('Only Generate control measures sends assessment context to this server. Use a locally downloaded model; runner cloud or forwarding features can route requests elsewhere.')
    st.divider()
    st.subheader('More Information')
    st.button('README',key='readme_nav',on_click=go_readme,width='stretch')
    st.button('Tutorial',key='tutorial_nav',on_click=start_tutorial,width='stretch')

if st.session_state.view=='readme':
    content=Path('README.md').read_text()
    if content.startswith('# '): content=content.split('\n',1)[1].lstrip()
    st.markdown(content)
    st.stop()

raw=upload.getvalue() if upload else Path('samples/'+{'CycloneDX':'cyclonedx.json','SPDX':'spdx.json','SPDX 3':'spdx3.json'}[sample]).read_bytes()
try:
    fmt,components,warnings=read_sbom(raw)
except (ValueError,TypeError,RecursionError) as exc:
    stop_collection(st.session_state.get('collection_job'))
    if upload:
        upload_status.error('Inventory could not be loaded. See the error in the main panel.')
    st.error(f'Cannot read inventory: {exc}')
    st.info('Remove the file to return to the sample inventory, or upload another SBOM. Your previous assessment stays in this session until a different valid inventory is loaded.')
    st.stop()
if upload:
    upload_status.success(f'Loaded {fmt} · {len(components):,} components')
for w in warnings: st.warning(w)
fingerprint=hashlib.sha256(raw).hexdigest()[:16]
context=fingerprint+('uploaded' if upload else 'sample')
if st.session_state.get('context') != context:
    migrated_upload=st.session_state.get('context') in (fingerprint+'Offline scenario',fingerprint+'Live GitHub')
    st.session_state.context=context
    if not migrated_upload:
        st.session_state.component_choice=components[0]['id']
        st.session_state.assessments={}
        st.session_state.pop('collection_job',None)
        st.session_state.pop('mission_undo',None)
        st.session_state.research_cache={}
        st.session_state.repository_overrides={}
        st.session_state.mapping_lookup_cache={}
        st.session_state.mapping_provenance={}
        st.session_state.pop('mapping_input_updates',None)
        st.session_state.pop('mapping_applied',None)
        st.session_state.pop('auto_mapping_summary',None)
        st.session_state.control_drafts={}
        st.session_state.control_draft_history={}
        st.session_state.control_contexts={}
        st.session_state.evidence={c['id']:synthetic(i) if mode=='Offline scenario' and not upload else unknown_evidence() for i,c in enumerate(components)}
evidence=st.session_state.evidence
if not upload and st.session_state.get('last_sample_mode') != mode:
    if mode == 'Live GitHub':
        for item in components:
            if evidence[item['id']].get('mode','').startswith('SYNTHETIC'): evidence[item['id']]=unknown_evidence()
    elif st.session_state.get('last_sample_mode') is not None:
        stop_collection(st.session_state.get('collection_job'))
        evidence.update({item['id']:synthetic(i) for i,item in enumerate(components)})
    st.session_state.last_sample_mode=mode
initialize_mission(components,st.session_state.assessments)
mapping_cache=st.session_state.setdefault('mapping_lookup_cache',{})
mapping_provenance=st.session_state.setdefault('mapping_provenance',{})
for ref,repo in st.session_state.pop('mapping_input_updates',{}).items():
    st.session_state['mapping_value_'+context+ref]=repo
for component in components:
    if component['id'] in st.session_state.get('repository_overrides',{}):
        component['repo']=st.session_state.repository_overrides[component['id']]
        component['mapping']='User-supplied repository; verify upstream identity' if component['repo'] else 'Unmapped by user'
        if component['id'] in mapping_provenance:
            component['mapping']=('Automatically mapped from package metadata; upstream identity unverified' if mapping_provenance[component['id']].get('method')=='automatic' else 'User-reviewed metadata suggestion; upstream identity not independently authenticated')
def build_payload():
    results={}
    for item in components:
        saved=st.session_state.assessments.get(item['id'],{'inputs':[3,3,3],'controls':[]})
        results[item['id']]=score(evidence[item['id']],saved['inputs'],saved['controls'])
    payload=sidecar(components,evidence,results,mode+' / '+('uploaded SBOM' if upload else 'bundled sample inventory'),st.session_state.get('research_cache',{}))
    payload['sbom_sha256']=hashlib.sha256(raw).hexdigest()
    payload['schema']='hephaestus-risk-sidecar/1.3'
    payload['mission_assignment']={'schema':'hephaestus-mission-assignment/1.0','method':'dependency-reach-v1','components':{ref:{k:deepcopy(v) for k,v in saved.items() if k!='controls'} for ref,saved in st.session_state.assessments.items()}}
    for item in payload['components']: item['assessment']['priority']=priority_value(item['assessment'])
    payload['generated_control_measures']={}
    payload['generated_control_history']=deepcopy(st.session_state.get('control_draft_history',{}))
    payload['repository_mapping_discovery']={'schema':'hephaestus-repository-mappings/1.0','records':mapping_cache,'component_associations':mapping_provenance}
    for item in components:
        draft=st.session_state.get('control_drafts',{}).get(item['id'])
        if draft:
            current=control_context(item,evidence[item['id']],results[item['id']],st.session_state.get('control_contexts',{}).get(item['id'],''))
            invalidate_draft(draft,draft['context_fingerprint']!=context_fingerprint(current))
            payload['generated_control_measures'][item['id']]=deepcopy(draft)
    return payload
@st.cache_data(show_spinner=False,max_entries=8)
def report_bytes(serialized): return pdf_report(json.loads(serialized))
if st.session_state.view=='report':
    payload=build_payload()
    st.subheader('Assessment report')
    st.plotly_chart(matrix_figure(payload),use_container_width=True)
    st.subheader('Ten highest-priority components')
    st.dataframe([{'Component':c['name']+' / '+c['version'],'Priority':priority_value(c['assessment']),
                   'Before':c['assessment']['exposure'],'After':c['assessment']['residual'],
                   'Coverage %':c['assessment']['completeness'],'Justification':justification(c)} for c in priorities(payload)],hide_index=True,width='stretch')
    unknown=sum(c['assessment']['exposure'] is None for c in payload['components'])
    st.caption(f'{unknown} component(s) have unknown exposure and are excluded from the matrix and ranking. '+payload['source'])
    st.subheader('Selected implementation plan')
    plan=selected_plan(payload)
    if plan:
        st.dataframe([{'Control':row['control'],'Actions':'\n'.join(row['actions']),
                       'Applies to':'\n'.join(row['components'])} for row in plan],hide_index=True,width='stretch')
    else: st.info('No controls selected for implementation')
    st.caption('Proposed, not verified implemented. Green points reflect selected modeled controls only. Full evidence and all drafts remain in JSON.')
    serialized=json.dumps(payload,indent=2)
    st.download_button('Download PDF report',report_bytes(serialized),file_name='hephaestus-assessment.pdf',mime='application/pdf')
    st.download_button('Download JSON sidecar',serialized,file_name='hephaestus-sidecar.json',mime='application/json')
    st.stop()
st.caption('01  Upload  /  02  Research  /  03  Assessment  /  04  Report')
if upload:
    st.caption('Uploaded inventory · Collect repository evidence and set mission inputs to assess components.')
elif mode=='Offline scenario':
    st.caption('Synthetic scenario · Values are fictional; they are not repository findings.')
else: st.caption('GitHub evidence · Verify repository mappings before relying on observations.')
coach('mapping')
unmapped=sum(not c['repo'] for c in components)
with st.expander('Inventory & repository mapping',expanded=bool(upload and unmapped) or tutorial_active() and st.session_state.get('tutorial_step')==1):
    if not upload:
        st.info(f'Viewing the bundled {sample} sample ({len(components):,} components). Use Import an SBOM in the sidebar to load your own inventory.')
    st.caption(f'{len(components)-unmapped:,} of {len(components):,} components have GitHub mappings. Package names and registry identifiers alone do not establish the upstream repository.')
    if st.button('Auto-map all components',key='auto_map_all',type='primary',disabled=not unmapped,help='Find and apply a single unambiguous GitHub repository for every unmapped component in the inventory. Processes all supported packages automatically, reuses cached metadata, and retries failed lookups. Sends package names and versions to public PyPI, npm, and Maven Central registries; GitHub-based Go paths are read locally. No tokens or mission inputs are sent. Existing mappings are preserved. No Tavily searches run.'):
        progress=st.progress(0,text='Auto-mapping components')
        summary=auto_map_all(components,mapping_cache,st.session_state.repository_overrides,evidence,mapping_provenance,
            progress=lambda i,n:progress.progress(i/n,text=f'Auto-mapping: {i:,} of {n:,} unique packages'))
        progress.empty()
        st.session_state.auto_mapping_summary=summary
        st.session_state.mapping_input_updates=summary['applied']
        if summary['applied']:
            st.session_state.pop('assessment_scope_'+context,None)
            st.session_state.pop('research_repos_'+context,None)
            st.session_state.pop('mapping_suggestions_'+context,None)
        st.rerun()
    if 'auto_mapping_summary' in st.session_state:
        summary=st.session_state.auto_mapping_summary
        message=f"Auto-mapped {len(summary['applied']):,} component(s). {unmapped:,} remain unresolved."
        if summary['applied']: st.success(message+' Continue to Collect all GitHub evidence below.')
        else: st.info(message+' Expand Mapping details and manual choices for unresolved packages.')
    if not unmapped:
        st.caption('No mapping needed: every component already has a repository. Continue to Collect all GitHub evidence below.')
    else:
        st.caption('One click finds and fills repository mappings across the whole inventory. Ambiguous or unavailable sources remain unresolved.')
    st.dataframe([{k:v for k,v in item.items() if k!='dependency'} for item in components],hide_index=True,width='stretch')
    with st.expander('Mapping details and manual choices'):
        types={}
        for item in components:
            if not item['repo']:
                kind=purl_type(item.get('purl'))
                types[kind]=types.get(kind,0)+1
        if types: st.caption('Unresolved package types: '+', '.join(f'{kind}: {count:,}' for kind,count in sorted(types.items()))+'.')
        lookup_rows=[]
        for item in components:
            ref=package_ref(item.get('purl'))
            record=mapping_cache.get(ref['key'],{}) if ref else {}
            if record:
                applied_method=mapping_provenance.get(item['id'],{}).get('method')
                status='auto-mapped' if applied_method=='automatic' else 'applied' if item['id'] in mapping_provenance else record['status']
                lookup_rows.append({'Component':item['name'],'ID':item['id'],'Status':status,'Suggested repositories':', '.join(c['repository'] for c in record['candidates']),'Metadata source':record['source_url'],'Details':record['message']})
            elif not item['repo']:
                lookup_rows.append({'Component':item['name'],'ID':item['id'],'Status':'unresolved','Suggested repositories':'','Metadata source':None,'Details':'Not looked up yet or no supported package URL. Run Auto-map all components, or enter a repository manually.'})
        if lookup_rows: st.dataframe(lookup_rows,hide_index=True,width='stretch',column_config={'Metadata source':st.column_config.LinkColumn('Metadata source')})
        options=candidate_options(components,mapping_cache)
        selected_mappings=st.multiselect('Reviewed repository suggestions',list(options),key='mapping_suggestions_'+context,help='Review the metadata source and verify each upstream project. Select one repository per component, then apply. Ambiguous candidates need an explicit choice. Nothing is selected automatically.')
        if st.button('Apply selected mappings',key='apply_mappings',disabled=not selected_mappings):
            try:
                count=apply_candidates(selected_mappings,options,st.session_state.repository_overrides,evidence,mapping_provenance)
                st.session_state.mapping_input_updates={ref:repo for ref,repo,_ in (options[value] for value in selected_mappings)}
                st.session_state.pop('assessment_scope_'+context,None)
                st.session_state.pop('research_repos_'+context,None)
                st.session_state.pop('mapping_suggestions_'+context,None)
                st.session_state.mapping_applied=count
                st.rerun()
            except ValueError as exc: st.error(str(exc))
        if st.session_state.get('mapping_applied'):
            st.success(f"Applied {st.session_state.pop('mapping_applied')} mapping(s). Select their repositories under Assessment evidence, then collect observations.")
        mapping_id=st.selectbox('Component repository mapping',[c['id'] for c in components],format_func=lambda ref:next(c['name']+' ['+ref+']' for c in components if c['id']==ref),key='mapping_component_'+context)
        mapping_component=next(c for c in components if c['id']==mapping_id)
        mapping_input_key='mapping_value_'+context+mapping_id
        if mapping_input_key not in st.session_state: st.session_state[mapping_input_key]=mapping_component['repo'] or ''
        mapping_value=st.text_input('GitHub repository (owner/repository or URL)',key=mapping_input_key,help='Use the verified upstream GitHub repository. Leave blank to remove a mapping. This does not change the original SBOM. Saving a changed mapping clears only that component\'s old observations.')
        if st.button('Save repository mapping',key='save_mapping'):
            try:
                new_repo=repository_input(mapping_value)
                if new_repo!=mapping_component['repo']:
                    st.session_state.setdefault('repository_overrides',{})[mapping_id]=new_repo
                    mapping_provenance.pop(mapping_id,None)
                    evidence[mapping_id]=unknown_evidence()
                    st.session_state.pop('assessment_scope_'+context,None)
                    st.session_state.pop('research_repos_'+context,None)
                st.rerun()
            except ValueError as exc: st.error(str(exc))
    st.download_button('Download imported SBOM' if upload else 'Download sample SBOM',raw,file_name='inventory.json',mime='application/json')
repos=list(dict.fromkeys(c['repo'] for c in components if c['repo']))
if upload:
    if unmapped:
        st.warning(f'{unmapped:,} component(s) need repository mappings for GitHub collection. Click Auto-map all components under Inventory & repository mapping. Components with mappings can already be assessed.')
    st.info('Upload imports the component list. Collect all GitHub evidence below to calculate exposure. Mission impact uses your three mission inputs; their initial values give 60.')

st.subheader('Assessment evidence',help='Collect the GitHub observations used by exposure and completeness. This is separate from optional Tavily contributor-source research. It never spends Tavily credits.')
coach('assessment_collection')
job=st.session_state.get('collection_job')
if job and job['signature']!=inventory_signature(components):
    job.update(state='cancelled',reason='Inventory or mappings changed. Start a new collection.')
if tutorial_active(): stop_collection(job)
busy=bool(job and job['state']=='running')
with st.expander('Advanced: collect a subset'):
    assessment_scope=st.multiselect('Repositories for assessment',repos,default=repos,
        key='assessment_scope_'+context,help='Optional subset; the main collection button always includes every mapped repository.')
    st.button('Collect selected repositories',key='collect_subset',disabled=not assessment_scope or busy,
        on_click=request_assessment_collection,args=(assessment_scope,))
action_left,action_right=st.columns(2)
action_left.button('Collect all GitHub evidence',key='collect_assessment',type='primary',disabled=not repos or busy,
    on_click=request_assessment_collection,args=(repos,),help='Collect all mapped repositories once, reusing session observations. No Tavily searches run.')
action_right.button('Retry missing evidence',key='retry_assessment',disabled=not repos or busy,
    on_click=request_assessment_retry,args=(repos,),help='Retry partial or failed collection across the entire mapped inventory.')
if not repos:
    st.info('Collection is unavailable because this inventory has no GitHub repository mappings. Click Auto-map all components first.')
st.caption(f'{len(repos):,} unique mapped repositories · {unmapped:,} unmapped components. Collection uses GitHub only. Missing evidence stays unknown.')
if st.session_state.pop('collect_assessment_requested',False):
    targets=[repo for repo in st.session_state.pop('assessment_requested_repos',repos) if repo in repos]
    st.session_state.collection_job=new_collection(components,evidence,targets,retry=st.session_state.pop('retry_assessment_requested',False))
    job=st.session_state.collection_job

@st.fragment(run_every=1 if job and job['state'] in ('running','paused') else None)
def collection_panel():
    job=st.session_state.get('collection_job')
    if not job: return
    left_stop,right_resume=st.columns(2)
    def resume_job():
        enable_live_mode()
        resume_collection(job,components)
    stopped=left_stop.button('Stop collection',key='stop_collection',disabled=job['state']!='running',
        on_click=stop_collection,args=(job,))
    resumed=right_resume.button('Resume collection',key='resume_collection',disabled=job['state']!='paused' or time.time()<job.get('resume_at',0),
        on_click=resume_job)
    if stopped or resumed: st.rerun()
    state_before=job['state']
    if job['state']=='running' and st.session_state.view=='assessment' and not tutorial_active():
        step_collection(job,components,evidence,token,use_scorecard)
    counts=collection_counts(job)
    total=len(job['repositories'])
    st.progress((job['cursor']+len(job['cached']))/max(1,total),text=f"GitHub collection: {job['cursor']+len(job['cached'])} / {total} repositories")
    st.caption(' · '.join(f'{key.title()}: {value}' for key,value in counts.items()))
    if job['reason']: st.info(job['reason'])
    if job['state']=='paused' and job.get('resume_at',0)>time.time():
        st.caption('Resume available after '+datetime.fromtimestamp(job['resume_at']).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z'))
    if job['state']=='complete': st.success('GitHub collection complete. Review coverage and any missing evidence below.')
    if state_before=='running' and job['state']!='running': st.rerun()
collection_panel()
st.subheader('Research',help='Review the mappings before selecting repositories. GitHub supplies governance observations; Tavily finds public contributor sources. Research never starts on upload or rerender.')
coach('research')
research_requested=st.session_state.get('research_requested')
if research_requested:
    st.session_state['research_repos_'+context]=[repo for repo in research_requested['repositories'] if repo in repos]
if 'research_repos_'+context not in st.session_state:
    st.session_state['research_repos_'+context]=repos[:5]
selected_repos=st.multiselect('Repositories to research',repos,max_selections=5,key='research_repos_'+context,help='Select up to five verified GitHub mappings. Components sharing one repository share a single research result.')
top_n=st.number_input('Contributors per repository',min_value=1,max_value=3,value=3,step=1,help='Top named non-bot contributors from the returned GitHub sample. Two web searches per contributor; this is a bounded sample, not a complete maintainer audit.')
st.caption(f'Up to {len(selected_repos)*top_n*2} Tavily searches per run (maximum 30). Deep extraction is disabled. Cached scopes are reused.')
if not tavily_key: st.caption('No Tavily key: GitHub observations can still be collected; contributor web research is skipped.')
st.button('Run research',disabled=not selected_repos,key='run_research',on_click=request_research,args=(selected_repos,),help='Collect GitHub observations and, if a Tavily key is supplied, run contributor-source searches for this scope. Clicking explicitly chooses live collection; no separate mode switch is required.')
failed=[r for r in selected_repos if st.session_state.research_cache.get(f'{r}:{top_n}',{}).get('status') in ('partial','failed')]
st.button('Retry failed research',disabled=not failed or not tavily_key,key='retry_research',on_click=request_research,args=(failed,True))
if not repos: st.caption('Research needs a verified GitHub repository mapping; accepted API credentials alone do not identify a component\'s upstream repository.')
elif not selected_repos: st.caption('Select one or more Repositories to research to enable Run research.')
if not failed: st.caption('Retry failed research is available after a partial or failed Tavily research run.')
research_requested=st.session_state.pop('research_requested',None)
if research_requested:
    retry=research_requested['retry']
    targets=[repo for repo in research_requested['repositories'] if repo in repos]
    progress=st.progress(0,text='Collecting repository evidence')
    collect_inventory(components,evidence,targets,token,use_scorecard,
        progress=lambda i,n,r:progress.progress(i/n,text=f'GitHub: {r}'))
    if tavily_key:
        run_batch(targets,int(top_n),token,tavily_key,project_id,st.session_state.research_cache,retry=retry,
                  progress=lambda i,n,r: progress.progress(i/n,text=f'Contributor research: {r}'))
    progress.empty()
    st.success('Research run complete. Review source status and any partial failures below.')
if st.session_state.research_cache:
    st.dataframe([{'Repository':r['repository'],'Status':r['status'],'Searches':r.get('searches_attempted',0),'Retrieved':r.get('retrieved_at')} for r in st.session_state.research_cache.values()],hide_index=True,width='stretch')
st.subheader('Assessment')
coach('mission_assignment')
with st.container(border=True):
    st.markdown('**Assign mission inputs across the inventory**',help='Dependency reach is a heuristic based on recorded direct and transitive dependents, not measured deployment. Criticality and recovery remain your judgment.')
    shared=st.columns(3)
    bulk_c=shared[0].number_input('Shared criticality',1,5,3,key='shared_criticality_'+context)
    bulk_r=shared[1].number_input('Shared recovery difficulty',1,5,3,key='shared_recovery_'+context)
    bulk_f=shared[2].number_input('Fallback reach',1,5,3,key='shared_fallback_'+context)
    replace=st.checkbox('Replace manual overrides',key='replace_mission_overrides')
    assign_col,undo_col=st.columns(2)
    def sync_mission_widgets():
        for ref,saved in st.session_state.assessments.items():
            for index,suffix in enumerate('abd'): st.session_state[context+ref+suffix]=saved['inputs'][index]
    def bulk_assign():
        st.session_state.mission_undo=assign_mission(components,st.session_state.assessments,int(bulk_c),int(bulk_r),int(bulk_f),replace)
        sync_mission_widgets()
    def bulk_undo():
        undo_mission(st.session_state.assessments,st.session_state.pop('mission_undo'))
        sync_mission_widgets()
    assign_col.button('Auto-assign mission impact',key='auto_mission',on_click=bulk_assign,type='primary')
    undo_col.button('Undo last bulk assignment',key='undo_mission',on_click=bulk_undo,disabled='mission_undo' not in st.session_state)
    st.caption('Dependent counts 0–1 / 2–4 / 5–9 / 10–24 / 25+ map to reach 1 / 2 / 3 / 4 / 5. Missing graphs use fallback reach. Manual overrides are preserved unless replaced.')
coach('component')
labels={c['id']:c['name']+' · '+c['version']+' ['+c['id']+']' for c in components}
# Consume selection before rendering the selector on the next rerun.
if 'pending_component' in st.session_state:
    st.session_state.component_choice=st.session_state.pop('pending_component')
selected=st.selectbox('Inspect component',list(labels),format_func=labels.get,key='component_choice', help='Select a component here or click its point on the matrix. Inputs and proposed controls are saved per component for this session.')
c=next(c for c in components if c['id']==selected)
if mode=='Live GitHub' or upload:
    col1,col2=st.columns([1,3])
    with col1: fetch=st.button('Fetch evidence',disabled=not c['repo'],on_click=enable_live_mode, help='Refresh repository metadata, branch settings, and up to 100 contributor records. All components mapped to this repository receive the same evidence. No separate evidence-mode switch is required.')
    if fetch:
        with st.spinner('Collecting public repository evidence…'):
            observation=collect(c['repo'],token,use_scorecard)
            for related in components:
                if related['repo']==c['repo']: evidence[related['id']]=observation
        st.session_state.evidence=evidence
left,right=st.columns([1.35,1])
with right:
    st.subheader('Mission & response', help='Set the consequences of this component failing or being compromised. Each input uses a 1–5 scale; higher means greater impact. Defaults are 3 and should be reviewed.')
    dependency=c.get('dependency',{})
    count=dependency.get('dependent_count')
    st.caption(f'Dependency graph: {count} direct/transitive dependent component(s).' if count is not None else 'Graph unavailable: shared fallback reach is used by auto-assignment.')
    saved=st.session_state.assessments.get(selected, {'inputs':[3,3,3], 'controls':[]})
    def mission_changed(index,suffix):
        saved=st.session_state.assessments[selected]
        saved['inputs'][index]=st.session_state[context+selected+suffix]
        saved['input_sources'][index]='manual'
    coach('criticality')
    a=st.slider('Operational criticality',1,5,saved['inputs'][0],key=context+selected+'a',on_change=mission_changed,args=(0,'a'), help='How essential is this component to the operation? 1: optional convenience. 2: minor degradation. 3: important function degraded. 4: core operation disrupted. 5: mission cannot continue.')
    coach('reach')
    b=st.slider('Deployment reach / blast radius',1,5,saved['inputs'][1],key=context+selected+'b',on_change=mission_changed,args=(1,'b'), help='How widely would a failure or compromise spread? 1: isolated test or single user. 2: one small service. 3: several services or one team. 4: multiple teams or production systems. 5: organization-wide or critical shared infrastructure.')
    coach('recovery')
    d=st.slider('Recovery difficulty',1,5,saved['inputs'][2],key=context+selected+'d',on_change=mission_changed,args=(2,'d'), help='How difficult would restoration or replacement be? 1: immediate rollback, negligible disruption. 2: routine recovery within hours. 3: coordinated work over days. 4: major rebuild or migration over weeks. 5: no practical replacement or prolonged loss of capability.')
    st.caption('Input sources: '+', '.join(saved['input_sources']))
st.session_state.assessments[selected]['inputs']=[a,b,d]
results={}
for item in components:
    ref=item['id']; prefix=context+ref
    saved=st.session_state.assessments.get(ref, {'inputs':[3,3,3], 'controls':[]})
    results[ref]=score(evidence[ref], saved['inputs'], saved['controls'])
s=results[selected]
with st.expander('Component assessment status',expanded=bool(upload)):
    st.dataframe([{'Component':item['name'],'GitHub repository':item['repo'] or 'Unmapped','Collection status':collection_status(evidence[item['id']],item['repo']),'Dependents':item.get('dependency',{}).get('dependent_count'),'Reach source':st.session_state.assessments[item['id']]['input_sources'][1],'Impact':results[item['id']]['impact'],'Exposure':display_score(results[item['id']]['exposure']),'Modeled residual':display_score(results[item['id']]['residual']),'Coverage':str(results[item['id']]['completeness'])+'%'} for item in components],hide_index=True,width='stretch')
with left:
    coach('matrix')
    st.subheader('Mission exposure matrix', help='Click a point to inspect a component. Horizontal: mission impact; vertical: observed exposure. Red circles show before controls, green diamonds show modeled after controls. Unknowns are omitted. Controls are selected below the assessment.')
    fig=matrix_figure({'components':[{**item,'assessment':results[item['id']]} for item in components]},selected)
    def choose_point():
        points=st.session_state['matrix'+context]['selection']['points']
        if points:
            ref=points[-1].get('customdata')
            if ref in labels:
                st.session_state.component_choice=ref
    st.plotly_chart(fig,use_container_width=True,key='matrix'+context,on_select=choose_point,selection_mode='points')
    unknown=sum(v['exposure'] is None for v in results.values())
    if unknown: st.caption(f'{unknown} component(s) have no scored observations and are omitted from the matrix; inspect them using the selector.')
cols=st.columns(4)
for col,label,value in zip(cols,['Mission impact','Observed exposure','Modeled residual','Evidence completeness'],[s['impact'],s['exposure'],s['residual'],str(s['completeness'])+'%']):
    metric_help={'Mission impact':'100 × sum of the three mission inputs / 15. Range: 20–100. Higher means greater consequence.', 'Observed exposure':'Weighted index of observed contributor/governance drivers, 0–100. Higher means greater observed exposure. Unknown factors are excluded; this is not a probability or evidence of malicious intent.', 'Modeled residual':'Exposure after illustrative reductions for selected controls. Range: 0–100. A lower value is a scenario result, not verified improvement.', 'Evidence completeness':'Percentage of model weights with observations, 0–100%. Higher means more coverage, not greater statistical confidence. Missing evidence may conceal exposure.'}
    col.metric(label,'Unknown' if value is None else value, help=metric_help[label])
if s['completeness']<60: st.warning('Limited evidence. A low observed score cannot establish low overall exposure; prioritize verification.')
if s['exposure'] is None:
    if not c['repo']: st.info('This component needs a verified GitHub repository mapping. Add one in Inventory & repository mapping, then click Collect all GitHub evidence.')
    elif evidence[selected].get('mode')=='unknown': st.info('No assessment evidence collected for this component yet. Click Collect all GitHub evidence to collect observations for every mapped repository.')
    else: st.error('Collection returned no scored observations for this component. Review the errors in Evidence and use Retry missing evidence after correcting the cause.')
st.subheader('Control measures',help='Select the actions you want in the implementation plan. Only checked controls appear in the PDF. Built-in controls have illustrative modeled effects; generated proposals have no automatic score effect.')
coach('controls')
saved=st.session_state.assessments[selected]
draft=st.session_state.get('control_drafts',{}).get(selected)
current_context=control_context(c,evidence[selected],s,st.session_state.get('control_contexts',{}).get(selected,''))
if draft: invalidate_draft(draft,draft['context_fingerprint']!=context_fingerprint(current_context))
def builtin_changed(key,widget):
    chosen=st.session_state.assessments[selected]['controls']
    if st.session_state[widget] and key not in chosen: chosen.append(key)
    elif not st.session_state[widget] and key in chosen: chosen.remove(key)
def choose_all_controls(value):
    st.session_state.assessments[selected]['controls']=list(CONTROLS) if value else []
    for key in CONTROLS: st.session_state.pop('builtin_'+context+selected+key,None)
    if draft and not draft.get('stale'):
        for card in prepare_draft(draft):
            card['selected']=value and selectable(card)
            st.session_state.pop('proposal_'+context+selected+draft['generation_id']+card['selection_id'],None)
        draft['reviewed']=any(card.get('selected') for card in prepare_draft(draft))
select_all,clear_all=st.columns(2)
select_all.button('Select all controls',key='select_all_controls',on_click=choose_all_controls,args=(True,))
clear_all.button('Clear selection',key='clear_controls',on_click=choose_all_controls,args=(False,))
for key,(title,baseline,factor,effect) in CONTROLS.items():
    widget='builtin_'+context+selected+key
    # Push durable selection state back to the browser after hidden-page cleanup.
    st.session_state[widget]=key in saved['controls']
    st.checkbox(title,key=widget,on_change=builtin_changed,args=(key,widget),
        help=f'Include this control in the implementation plan. Assumed {effect:.0%} reduction of the {factor} driver; no reduction when that evidence is unknown. {baseline}. This does not implement or verify a safeguard.')
coach('local_controls')
st.caption('Generate proposals with your local model, then check individual actions to include them. Generated actions do not change scores.')
operational_context=st.text_area('Operational context for controls (optional)',value=st.session_state.get('control_contexts',{}).get(selected,''),max_chars=2000,key='control_context_'+context+selected,help='Only this component’s assessment and operational context are sent to your configured local endpoint; credentials and the full SBOM are excluded.')
st.session_state.setdefault('control_contexts',{})[selected]=operational_context
draft_context=control_context(c,evidence[selected],s,operational_context)
with st.expander('Context sent to the local model'): st.json(draft_context)
if not llm_can_generate: st.caption('Connect a local model in the sidebar or supply its model ID to enable generation.')
if st.button('Generate control measures',key='generate_controls',disabled=not llm_can_generate,type='primary'):
    with st.spinner(f'Generating controls with {llm_model}; this can take up to {llm_timeout} seconds…'):
        try:
            draft=generate_controls(llm_provider,llm_endpoint,llm_model,draft_context,llm_key,int(llm_timeout),secrets=(token,tavily_key,project_id),structured=llm_structured)
            prepare_draft(draft)
            previous=st.session_state.get('control_drafts',{}).get(selected)
            if previous:
                st.session_state.setdefault('control_draft_history',{}).setdefault(selected,[]).append(deepcopy(previous))
            st.session_state.setdefault('control_drafts',{})[selected]=draft
        except ValueError as exc: st.error(str(exc))
draft=st.session_state.get('control_drafts',{}).get(selected)
if draft:
    stale=draft['context_fingerprint']!=context_fingerprint(draft_context)
    cards=invalidate_draft(draft,stale)
    stale=draft['stale']
    if stale: st.warning('These measures are out of date. Their report selections have been cleared; regenerate and review the new proposals.')
    st.caption(f"Unverified proposals · {draft['provider']} · {draft['model']} · {draft['generated_at']}")
    if draft.get('text'):
        with st.expander('Original plain-text draft'): st.text(draft['text'])
        st.caption('Review the extracted action cards, or add an action from the draft. Editing a card clears its selection.')
        with st.form('add_action_'+context+selected+draft['generation_id']):
            action_title=st.text_input('New action title',max_chars=160)
            action_text=st.text_area('New action text',max_chars=4000)
            add_action=st.form_submit_button('Add action card',disabled=stale)
        if add_action:
            if action_title.strip() and action_text.strip():
                draft['action_cards'].append({'title':action_title.strip(),'actions':[action_text.strip()],'editable':True})
                prepare_draft(draft)
                st.rerun()
            else: st.error('Enter a title and action text.')
    def proposal_changed(card,widget):
        card['selected']=st.session_state[widget]
        draft['reviewed']=any(item.get('selected') for item in prepare_draft(draft))
    def edit_card(card,title_key,text_key,select_key):
        title=st.session_state[title_key].strip()
        action=st.session_state[text_key].strip()
        card.update(title=title,actions=[action],selected=False)
        st.session_state[select_key]=False
    for measure in cards:
        widget='proposal_'+context+selected+draft['generation_id']+measure['selection_id']
        st.session_state[widget]=bool(measure.get('selected')) and not stale
        with st.container(border=True):
            check,title_col=st.columns([2,3])
            check.checkbox('Include in implementation plan',key=widget,disabled=stale or not selectable(measure),on_change=proposal_changed,args=(measure,widget),help='Check after reviewing this action. Includes this proposal for this component in the PDF; it does not prove implementation or change the score.')
            title_col.text(measure['title'])
            if measure.get('editable'):
                title_key=widget+'_title';text_key=widget+'_text'
                if title_key not in st.session_state: st.session_state[title_key]=measure['title']
                if text_key not in st.session_state: st.session_state[text_key]='\n'.join(measure['actions'])
                st.text_input('Action title',key=title_key,disabled=stale,max_chars=160,on_change=edit_card,args=(measure,title_key,text_key,widget))
                st.text_area('Action text',key=text_key,disabled=stale,max_chars=4000,on_change=edit_card,args=(measure,title_key,text_key,widget))
            else:
                for action in measure.get('actions',[]): st.text('• '+action)
                with st.expander('Reason and verification'):
                    st.text(measure.get('rationale',''))
                    st.text(measure.get('verification',''))
                    for source in measure.get('source_urls',[]): st.link_button('Supplied assessment source',source)
    draft['reviewed']=any(card.get('selected') for card in cards) and not stale
selected_count=len(saved['controls'])+sum(card.get('selected',False) for card in prepare_draft(draft) if not draft.get('stale')) if draft else len(saved['controls'])
st.caption(f'{selected_count} control(s) selected for this component. Only checked, current actions appear in the report; JSON retains all drafts and selection status.')
coach('evidence')
t1,t2,t3=st.tabs(['Evidence','Method','Export'])
with t1:
    st.subheader(c['name']+' · '+c['version'], help='Repository observations describe the current repository, not necessarily this package release. SBOM mappings are not independently authenticated.')
    e=evidence[selected]
    st.write('Evidence origin:',e.get('mode','unknown'))
    st.caption('Retrieved: '+str(e.get('fetched_at') or 'Not a live observation'))
    if c['repo']: st.link_button('Open mapped GitHub repository','https://github.com/'+c['repo'])
    st.caption('Repository mapping: '+c['mapping'])
    st.dataframe([{'driver':k,'observed value':str(e['factors'][k]) if e.get('factors',{}).get(k) is not None else 'Unknown','weight':w} for k,w in __import__('core').WEIGHTS.items()],hide_index=True,width='stretch')
    for note in e.get('notes',[]): st.write('• '+note)
    for source in e.get('sources',[]): st.markdown(f"[Source · HTTP {source['http_status']}]({source['url']})")
    if e.get('contributors'):
        st.dataframe(e['contributors'],column_config={'url':st.column_config.LinkColumn('Contributor profile')},hide_index=True,width='stretch')
    st.caption('Identity and U.S. Person status: unverified. Authorized attestation required.')
    for research in st.session_state.research_cache.values():
        if research.get('repository')!=c.get('repo'): continue
        st.subheader('Contributor source research')
        st.caption(f"{research['status']} · {research.get('retrieved_at')} · upstream {research.get('upstream_revision')}")
        st.caption('Heuristic source matches require human confirmation. Research does not affect the score or evidence completeness.')
        if research.get('error'): st.warning(research['error'])
        for person in research.get('contributors',[]):
            with st.expander(person['login']+' · '+person['outcome']):
                st.write('Queries:',person['queries'])
                for err in person.get('errors',[]): st.warning(err)
                for source in person['sources']:
                    st.link_button(source['title'],source['url'])
                    st.caption('Heuristic '+source['heuristic_match']+' match · confirm identity before use')
                    st.text(source['excerpt'])
    if 'scorecard' in e:
        with st.expander('Scorecard context — excluded from this model'): st.json(e['scorecard'])
with t2:
    st.markdown('''**Mission impact** = 100 × (criticality + deployment reach + recovery difficulty) / 15. Each analyst input ranges 1–5; minimum impact is 20.

**Observed exposure** = 100 × Σ(weight × observed factor) / Σ(known factor weights). Unknowns are excluded, never set to zero. Factor weights: contributor concentration 30, archived repository 15, direct-commit enforcement gap 30, review gap 25.

**Completeness** = sum of known weights / 100. This measures model coverage, not truth, identity assurance, or statistical confidence.

**Modeled residual** uses the same denominator with selected factors multiplied by (1 − assumed reduction). It does not increase completeness. Effects are illustrative analyst assumptions, not empirically calibrated estimates.

Concentration = largest commit share in the returned contributor sample. Archived = 1 if archived, else 0. Enforcement/review gaps range from 0 (observed safeguard) to 1 (observed gap). Live direct-commit enforcement stays unknown because the available branch indicator cannot prove enforcement. Review settings are partial evidence, subject to bypasses. Present-day repository evidence does not establish the security of an SBOM release.

The 50-point quadrant boundaries are navigation aids, not validated acceptance thresholds. Compare components only with attention to evidence coverage and mission context.''')
    st.json(s)
    st.markdown(f'[OSPS Baseline v2026.08.28]({BASELINE}) · [GitHub REST documentation](https://docs.github.com/en/rest/repos/repos) · [Streamlit selection API](https://docs.streamlit.io/develop/api-reference/charts/st.plotly_chart)')
with t3:
    st.write('Finish the assessment to review all components and download a PDF report and JSON evidence sidecar. Missing observations remain unknown.')
coach('finish')
def finish_assessment():
    stop_collection(st.session_state.get('collection_job'))
    st.session_state.view='report'
st.button('Finish assessment',key='finish_assessment',type='primary',on_click=finish_assessment)
