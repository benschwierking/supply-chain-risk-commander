import base64
import hashlib
import json
import os
from pathlib import Path
import streamlit as st
import plotly.graph_objects as go
from core import read_sbom, repository_input, score, sidecar, CONTROLS, BASELINE
from evidence import collect, collect_inventory, collection_status, unknown_evidence, synthetic
from research import run_batch
from reporting import pdf_report
from tutorial import coach, start as start_tutorial, active as tutorial_active
from connections import check_credential, connection_key
from local_llm import PROVIDERS, local_base_url, list_models, preferred_model, control_context, context_fingerprint, generate_controls

st.set_page_config(page_title='HEPHAESTUS', page_icon='assets/favicon.svg', layout='wide', initial_sidebar_state='expanded')
network_image=base64.b64encode(Path('assets/network.png').read_bytes()).decode()
st.markdown("<style>" + Path('assets/theme.css').read_text() + ":root{--network-image:url(data:image/png;base64,"+network_image+");}</style>", unsafe_allow_html=True)
if 'view' not in st.session_state: st.session_state.view='assessment'
def go_assessment(): st.session_state.view='assessment'
def go_readme(): st.session_state.view='readme'
def request_assessment_collection(repositories):
    st.session_state.evidence_mode='Live GitHub'
    st.session_state.collect_assessment_requested=True
    st.session_state.assessment_requested_repos=list(repositories)
def request_assessment_retry(repositories):
    request_assessment_collection(repositories)
    st.session_state.retry_assessment_requested=True
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
    mode=st.radio('Evidence mode',['Offline scenario','Live GitHub'],key='evidence_mode', help='Offline evidence is synthetic for bundled samples only. Uploaded SBOMs start without evidence. Collect assessment evidence switches to Live GitHub and collects observations after you click; upload alone does not start requests.')
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
    if upload:
        upload_status.error('Inventory could not be loaded. See the error in the main panel.')
    st.error(f'Cannot read inventory: {exc}')
    st.info('Remove the file to return to the sample inventory, or upload another SBOM. Your previous assessment stays in this session until a different valid inventory is loaded.')
    st.stop()
if upload:
    upload_status.success(f'Loaded {fmt} · {len(components):,} components')
for w in warnings: st.warning(w)
fingerprint=hashlib.sha256(raw).hexdigest()[:16]
context=fingerprint+('uploaded' if upload else mode)
if st.session_state.get('context') != context:
    migrated_upload=bool(upload and st.session_state.get('context') in (fingerprint+'Offline scenario',fingerprint+'Live GitHub'))
    st.session_state.context=context
    if not migrated_upload:
        st.session_state.component_choice=components[0]['id']
        st.session_state.assessments={}
        st.session_state.research_cache={}
        st.session_state.repository_overrides={}
        st.session_state.control_drafts={}
        st.session_state.control_contexts={}
        st.session_state.evidence={c['id']:synthetic(i) if mode=='Offline scenario' and not upload else unknown_evidence() for i,c in enumerate(components)}
evidence=st.session_state.evidence
for component in components:
    if component['id'] in st.session_state.get('repository_overrides',{}):
        component['repo']=st.session_state.repository_overrides[component['id']]
        component['mapping']='User-supplied repository; verify upstream identity' if component['repo'] else 'Unmapped by user'
def build_payload():
    results={}
    for item in components:
        saved=st.session_state.assessments.get(item['id'],{'inputs':[3,3,3],'controls':[]})
        results[item['id']]=score(evidence[item['id']],saved['inputs'],saved['controls'])
    payload=sidecar(components,evidence,results,mode+' / '+('uploaded SBOM' if upload else 'bundled sample inventory'),st.session_state.get('research_cache',{}))
    payload['sbom_sha256']=hashlib.sha256(raw).hexdigest()
    payload['schema']='hephaestus-risk-sidecar/1.2'
    payload['generated_control_measures']={}
    for item in components:
        draft=st.session_state.get('control_drafts',{}).get(item['id'])
        if draft:
            current=control_context(item,evidence[item['id']],results[item['id']],st.session_state.get('control_contexts',{}).get(item['id'],''))
            payload['generated_control_measures'][item['id']]={**draft,'stale':draft['context_fingerprint']!=context_fingerprint(current)}
    return payload
@st.cache_data(show_spinner=False,max_entries=8)
def report_bytes(serialized): return pdf_report(json.loads(serialized))
if st.session_state.view=='report':
    payload=build_payload()
    st.subheader('Assessment report',help='All components are included, including those with missing observations. Proposed controls remain modeled assumptions.')
    st.dataframe([{'Component':c['name'],'Impact':c['assessment']['impact'],'Exposure':display_score(c['assessment']['exposure']),'Residual':display_score(c['assessment']['residual']),'Coverage %':c['assessment']['completeness'],'Evidence status':collection_status(c['evidence'],c.get('repo'))} for c in payload['components']],hide_index=True,width='stretch')
    st.caption('Impact is calculated from your mission inputs. The starting values of 3/5 each give 60; review them for each component. Unknown exposure means observations are missing, not that exposure is zero.')
    if payload['generated_control_measures']: st.caption('Generated control measures are included in the downloads with model provenance and review status. Out-of-date drafts remain clearly labeled and do not affect scoring.')
    for limitation in payload['limitations']: st.caption(limitation)
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
    st.caption(f'{len(components)-unmapped:,} of {len(components):,} components have GitHub mappings. Package names and registry identifiers alone do not establish the upstream repository.')
    st.dataframe(components,hide_index=True,width='stretch')
    mapping_id=st.selectbox('Component repository mapping',[c['id'] for c in components],format_func=lambda ref:next(c['name']+' ['+ref+']' for c in components if c['id']==ref),key='mapping_component_'+context)
    mapping_component=next(c for c in components if c['id']==mapping_id)
    mapping_value=st.text_input('GitHub repository (owner/repository or URL)',value=mapping_component['repo'] or '',key='mapping_value_'+context+mapping_id,help='Use the verified upstream GitHub repository. Leave blank to remove a mapping. This does not change the original SBOM. Saving a changed mapping clears only that component\'s old observations.')
    if st.button('Save repository mapping',key='save_mapping'):
        try:
            new_repo=repository_input(mapping_value)
            if new_repo!=mapping_component['repo']:
                st.session_state.setdefault('repository_overrides',{})[mapping_id]=new_repo
                evidence[mapping_id]=unknown_evidence()
                st.session_state.pop('assessment_scope_'+context,None)
            st.rerun()
        except ValueError as exc: st.error(str(exc))
    st.download_button('Download imported SBOM' if upload else 'Download sample SBOM',raw,file_name='inventory.json',mime='application/json')
repos=list(dict.fromkeys(c['repo'] for c in components if c['repo']))
if upload:
    if unmapped:
        st.warning(f'{unmapped:,} component(s) need repository mappings before GitHub evidence can be collected. Add them under Inventory & repository mapping.')
    st.info('Upload imports the component list. Collect assessment evidence below to calculate exposure. Mission impact uses your three mission inputs; their initial values give 60.')

st.subheader('Assessment evidence',help='Collect the GitHub observations used by exposure and completeness. This is separate from optional Tavily contributor-source research. It never spends Tavily credits.')
coach('assessment_collection')
if st.session_state.get('collect_assessment_requested'):
    st.session_state['assessment_scope_'+context]=[repo for repo in st.session_state.get('assessment_requested_repos',[]) if repo in repos]
if 'assessment_scope_'+context not in st.session_state:
    st.session_state['assessment_scope_'+context]=repos[:25]
assessment_scope=st.multiselect('Repositories for assessment',repos,max_selections=25,key='assessment_scope_'+context,help='Collect up to 25 repositories per run. Every component sharing a repository receives the same observations. Choose another group for larger inventories. Collected observations stay cached in this session.')
st.caption('Collection uses GitHub only; a Tavily key is not needed. Up to 25 repositories per run. Missing observations stay unknown and are listed in Evidence.')
action_left,action_right=st.columns(2)
action_left.button('Collect assessment evidence',key='collect_assessment',type='primary',disabled=not assessment_scope,on_click=request_assessment_collection,args=(assessment_scope,),help='Switch to Live GitHub and collect repository metadata, available branch settings, and contributors for the selected repositories. Previously collected observations are reused.')
action_right.button('Retry missing evidence',key='retry_assessment',disabled=not assessment_scope,on_click=request_assessment_retry,args=(assessment_scope,),help='Retry selected repositories with failed or partial collection, for example after replacing an expired token. Repositories without failures use cached observations.')
collection_requested=st.session_state.pop('collect_assessment_requested',False)
collection_retry=st.session_state.pop('retry_assessment_requested',False)
if collection_requested:
    requested_repos=st.session_state.pop('assessment_requested_repos',assessment_scope)
    progress=st.progress(0,text='Collecting assessment evidence')
    count=collect_inventory(components,evidence,requested_repos,token,use_scorecard,retry=collection_retry,
        progress=lambda i,n,r:progress.progress(i/n,text=f'GitHub {i}/{n}: {r}'))
    progress.empty()
    available=sum(bool(evidence[c['id']].get('factors')) for c in components if c['repo'] in requested_repos)
    if available:
        st.success(f'Collection finished: {available:,} component(s) have observations. Queried {count} repositories; reused session evidence where available. Review evidence coverage below.')
    else:
        st.error('No scored observations returned. Review Evidence for HTTP errors, check repository mappings and your token, then use Retry missing evidence.')
st.subheader('Research',help='Review the mappings before selecting repositories. GitHub supplies governance observations; Tavily finds public contributor sources. Research never starts on upload or rerender.')
coach('research')
selected_repos=st.multiselect('Repositories to research',repos,default=repos[:5],max_selections=5,key='research_repos_'+context,help='Select up to five verified GitHub mappings. Components sharing one repository share a single research result.')
top_n=st.number_input('Contributors per repository',min_value=1,max_value=3,value=3,step=1,help='Top named non-bot contributors from the returned GitHub sample. Two web searches per contributor; this is a bounded sample, not a complete maintainer audit.')
st.caption(f'Up to {len(selected_repos)*top_n*2} Tavily searches per run (maximum 30). Deep extraction is disabled. Cached scopes are reused.')
if not tavily_key: st.caption('No Tavily key: GitHub observations can still be collected; contributor web research is skipped.')
run=st.button('Run research',disabled=mode!='Live GitHub' or not selected_repos,key='run_research')
failed=[r for r in selected_repos if st.session_state.research_cache.get(f'{r}:{top_n}',{}).get('status') in ('partial','failed')]
retry=st.button('Retry failed research',disabled=not failed or not tavily_key or mode!='Live GitHub',key='retry_research')
if run or retry:
    targets=failed if retry else selected_repos
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
coach('component')
labels={c['id']:c['name']+' · '+c['version']+' ['+c['id']+']' for c in components}
# Consume selection before rendering the selector on the next rerun.
if 'pending_component' in st.session_state:
    st.session_state.component_choice=st.session_state.pop('pending_component')
selected=st.selectbox('Inspect component',list(labels),format_func=labels.get,key='component_choice', help='Select a component here or click its point on the matrix. Inputs and proposed controls are saved per component for this session.')
c=next(c for c in components if c['id']==selected)
if mode=='Live GitHub':
    col1,col2=st.columns([1,3])
    with col1: fetch=st.button('Fetch evidence',disabled=not c['repo'], help='Refresh repository metadata, branch settings, and up to 100 contributor records. All components mapped to this repository receive the same evidence.')
    if fetch:
        with st.spinner('Collecting public repository evidence…'):
            observation=collect(c['repo'],token,use_scorecard)
            for related in components:
                if related['repo']==c['repo']: evidence[related['id']]=observation
        st.session_state.evidence=evidence
left,right=st.columns([1.35,1])
with right:
    st.subheader('Mission & response', help='Set the consequences of this component failing or being compromised. Each input uses a 1–5 scale; higher means greater impact. Defaults are 3 and should be reviewed.')
    st.caption('Mission impact is your operational judgment, not a value extracted from the SBOM. Starting inputs of 3/5 each produce 60; set each scale for this component.')
    saved=st.session_state.assessments.get(selected, {'inputs':[3,3,3], 'controls':[]})
    coach('criticality')
    a=st.slider('Operational criticality',1,5,saved['inputs'][0],key=context+selected+'a', help='How essential is this component to the operation? 1: optional convenience. 2: minor degradation. 3: important function degraded. 4: core operation disrupted. 5: mission cannot continue.')
    coach('reach')
    b=st.slider('Deployment reach / blast radius',1,5,saved['inputs'][1],key=context+selected+'b', help='How widely would a failure or compromise spread? 1: isolated test or single user. 2: one small service. 3: several services or one team. 4: multiple teams or production systems. 5: organization-wide or critical shared infrastructure.')
    coach('recovery')
    d=st.slider('Recovery difficulty',1,5,saved['inputs'][2],key=context+selected+'d', help='How difficult would restoration or replacement be? 1: immediate rollback, negligible disruption. 2: routine recovery within hours. 3: coordinated work over days. 4: major rebuild or migration over weeks. 5: no practical replacement or prolonged loss of capability.')
    coach('controls')
    controls=st.multiselect('Model mitigation controls',list(CONTROLS),format_func=lambda k:CONTROLS[k][0],default=saved['controls'],key=context+selected+'controls', help='What-if controls for this component. They reduce selected drivers using illustrative assumptions; they do not change upstream settings or establish implementation, compliance, or effectiveness.')
    for key in controls:
        title,control,factor,effect=CONTROLS[key]
        st.markdown(f'**{control}** · {int(effect*100)}% assumed reduction in {factor} driver. [Baseline guidance]({BASELINE})')
st.session_state.assessments[selected]={'inputs':[a,b,d], 'controls':controls}
results={}
for item in components:
    ref=item['id']; prefix=context+ref
    saved=st.session_state.assessments.get(ref, {'inputs':[3,3,3], 'controls':[]})
    results[ref]=score(evidence[ref], saved['inputs'], saved['controls'])
s=results[selected]
with st.expander('Component assessment status',expanded=bool(upload)):
    st.dataframe([{'Component':item['name'],'GitHub repository':item['repo'] or 'Unmapped','Collection status':collection_status(evidence[item['id']],item['repo']),'Impact':results[item['id']]['impact'],'Exposure':display_score(results[item['id']]['exposure']),'Modeled residual':display_score(results[item['id']]['residual']),'Coverage':str(results[item['id']]['completeness'])+'%'} for item in components],hide_index=True,width='stretch')
with left:
    coach('matrix')
    st.subheader('Mission exposure matrix', help='Click a point to inspect a component. Horizontal: mission impact, 20–100. Vertical: observed governance/contributor exposure, 0–100. Circles show baseline; diamonds show modeled residual. Point size shows evidence completeness. Quadrant dividers at 50 are visual guides, not acceptance thresholds.')
    fig=go.Figure()
    for x0,x1,y0,y1,color in [(0,50,0,50,'#202b28'),(50,100,0,50,'#302d25'),(0,50,50,100,'#30282b'),(50,100,50,100,'#47282b')]:
        fig.add_shape(type='rect',x0=x0,x1=x1,y0=y0,y1=y1,fillcolor=color,line_width=0,layer='below',opacity=.65)
    for item in components:
        v=results[item['id']]
        if v['exposure'] is None: continue
        fig.add_trace(go.Scatter(x=[v['impact'],v['impact']],y=[v['exposure'],v['residual']],mode='lines',line=dict(color='#777b80',width=1),showlegend=False,hoverinfo='skip'))
        for residual,symbol,color in [(False,'circle','#b4b7bc'),(True,'diamond','#cf454a')]:
            fig.add_trace(go.Scatter(x=[v['impact']],y=[v['residual'] if residual else v['exposure']],mode='markers',customdata=[item['id']],name=item['name']+(' modeled' if residual else ' baseline'),marker=dict(size=12+v['completeness']/7,symbol=symbol,color=color,line=dict(color='#ffffff' if item['id']==selected else color,width=2)),hovertemplate='%{text}<br>Mission impact %{x}<br>Exposure %{y}<extra></extra>',text=[item['name']+f" · {v['completeness']}% complete"],showlegend=False))
    fig.update_layout(height=450,margin=dict(l=15,r=15,t=15,b=15),paper_bgcolor='#0b0d0f',plot_bgcolor='#0b0d0f',font=dict(color='#e5e6e8',family='Arial, sans-serif'),xaxis=dict(title='MISSION IMPACT →',range=[-3,103],gridcolor='#35383c'),yaxis=dict(title='CONTRIBUTOR / GOVERNANCE EXPOSURE →',range=[-3,103],gridcolor='#35383c'),clickmode='event+select')
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
    if not c['repo']: st.info('This component needs a verified GitHub repository mapping. Add one in Inventory & repository mapping, then collect assessment evidence.')
    elif evidence[selected].get('mode')=='unknown': st.info('No assessment evidence collected for this component yet. Include its repository in Repositories for assessment and click Collect assessment evidence.')
    else: st.error('Collection returned no scored observations for this component. Review the errors in Evidence and use Retry missing evidence after correcting the cause.')
st.subheader('Control measures',help='Use your local LLM to draft actions and verification steps for the selected component. Generated text is unverified and has no automatic effect on scores or evidence coverage.')
coach('local_controls')
st.caption('Generate proposals with your chosen local model. Review each measure before use. To simulate score reductions, use Model mitigation controls above; generated proposals do not change scores.')
operational_context=st.text_area('Operational context for controls (optional)',value=st.session_state.get('control_contexts',{}).get(selected,''),max_chars=2000,key='control_context_'+context+selected,help='Describe constraints, deployment, ownership, or recovery options that should shape the proposals. Only this selected component\'s assessment and this text are sent to the local endpoint; credentials and the full SBOM are excluded.')
st.session_state.setdefault('control_contexts',{})[selected]=operational_context
draft_context=control_context(c,evidence[selected],s,operational_context)
with st.expander('Context sent to the local model'):
    st.json(draft_context)
if not llm_can_generate: st.caption('Open Local LLM connection in the sidebar. Connect and select a model, or supply a model ID manually, to enable generation.')
if st.button('Generate control measures',key='generate_controls',disabled=not llm_can_generate,type='primary'):
    with st.spinner(f'Generating controls with {llm_model}; this can take up to {llm_timeout} seconds…'):
        try:
            draft=generate_controls(llm_provider,llm_endpoint,llm_model,draft_context,llm_key,int(llm_timeout),secrets=(token,tavily_key,project_id),structured=llm_structured)
            st.session_state.setdefault('control_drafts',{})[selected]=draft
        except ValueError as exc: st.error(str(exc))
draft=st.session_state.get('control_drafts',{}).get(selected)
if draft:
    stale=draft['context_fingerprint']!=context_fingerprint(draft_context)
    if stale: st.warning('The assessment or operational context changed after generation. These measures are out of date; regenerate them before relying on them.')
    st.caption(f"Unverified model draft · {draft['provider']} · {draft['model']} · {draft['generated_at']}")
    if draft.get('text'):
        st.info('This model returned an unstructured draft. Review its text directly; no control fields or score reductions have been inferred from it.')
        st.text(draft['text'])
    for measure in draft['controls']:
        with st.container(border=True):
            st.text(f"{measure['id']}. {measure['title']}")
            st.caption('Proposed implementation priority: '+measure['priority'])
            st.text(measure['rationale'])
            for step in measure['actions']: st.text('• '+step)
            st.text('Verify completion: '+measure['verification'])
            for source in measure['source_urls']: st.link_button('Supplied assessment source',source)
    review_key='controls_reviewed_'+context+selected+draft['generated_at']
    reviewed=st.checkbox('I have reviewed these proposed control measures',value=draft.get('reviewed',False),key=review_key,disabled=stale,help='Records your review in exports. It does not prove implementation or effectiveness, and does not change scoring.')
    draft['reviewed']=reviewed and not stale
    st.caption('Included in PDF and JSON reports with model provenance, review status, and an out-of-date flag when applicable.')
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
def finish_assessment(): st.session_state.view='report'
st.button('Finish assessment',key='finish_assessment',type='primary',on_click=finish_assessment)
