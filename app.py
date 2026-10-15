import base64
import hashlib
import json
import os
from pathlib import Path
import streamlit as st
import plotly.graph_objects as go
from core import parse_sbom, score, sidecar, CONTROLS, BASELINE
from evidence import collect, synthetic
from research import run_batch
from reporting import pdf_report
from tutorial import coach, start as start_tutorial, active as tutorial_active

st.set_page_config(page_title='HEPHAESTUS', page_icon='assets/favicon.svg', layout='wide', initial_sidebar_state='expanded')
network_image=base64.b64encode(Path('assets/network.png').read_bytes()).decode()
st.markdown("<style>" + Path('assets/theme.css').read_text() + ":root{--network-image:url(data:image/png;base64,"+network_image+");}</style>", unsafe_allow_html=True)
if 'view' not in st.session_state: st.session_state.view='assessment'
def go_assessment(): st.session_state.view='assessment'
def go_readme(): st.session_state.view='readme'

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
    mode=st.radio('Evidence mode',['Offline scenario','Live GitHub'], help='Offline evidence is synthetic. Uploaded SBOMs never inherit demo findings.')
    upload=st.file_uploader('Import an SBOM',type=['json','jsonld'], help='CycloneDX, SPDX 2.x JSON, or SPDX 3 JSON-LD, up to 10 MB. Repository links come from the file and require verification.')
    sample=st.selectbox('Sample inventory',['CycloneDX','SPDX','SPDX 3'], help='Bundled example inventories. Offline scenario values are synthetic, not findings about the listed projects.')
    token=st.text_input('GitHub token (optional)',type='password',value=os.getenv('GITHUB_TOKEN',''), help='Token stays in this session and is never exported. Public requests can work without one. A token may increase rate limits; branch protection evidence may require additional permissions.')
    use_scorecard=st.checkbox('Include OpenSSF Scorecard',False, help='Fetch optional repository security-check context. Scorecard results are shown separately and do not affect this model.')
    tavily_key=st.text_input('Tavily API key (optional)',type='password',value=os.getenv('TAVILY_API_KEY',''), help='Enables contributor web-source research. The key stays in session and is never exported. Queries send public GitHub names, handles, and repository identifiers to Tavily only when you run research.')
    project_id=st.text_input('Tavily project ID (optional)',value=os.getenv('TAVILY_PROJECT_ID',''),help='Optional usage attribution for Tavily requests. Not included in exported reports.')
    coach('connections')
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
    fmt,components,warnings=parse_sbom(json.loads(raw))
except (ValueError,TypeError,RecursionError) as exc:
    st.error(f'Cannot read inventory: {exc}'); st.stop()
for w in warnings: st.warning(w)
fingerprint=hashlib.sha256(raw).hexdigest()[:16]
context=fingerprint+mode
if st.session_state.get('context') != context:
    st.session_state.context=context
    st.session_state.component_choice=components[0]['id']
    st.session_state.assessments={}
    st.session_state.research_cache={}
    st.session_state.evidence={c['id']:synthetic(i) if mode=='Offline scenario' and not upload else {'mode':'unknown','factors':{},'notes':['Fetch live evidence to assess this uploaded component.'],'sources':[]} for i,c in enumerate(components)}
evidence=st.session_state.evidence
def build_payload():
    results={}
    for item in components:
        saved=st.session_state.assessments.get(item['id'],{'inputs':[3,3,3],'controls':[]})
        results[item['id']]=score(evidence[item['id']],saved['inputs'],saved['controls'])
    payload=sidecar(components,evidence,results,mode+' / '+('uploaded SBOM' if upload else 'bundled synthetic scenario'),st.session_state.get('research_cache',{}))
    payload['sbom_sha256']=hashlib.sha256(raw).hexdigest()
    return payload
@st.cache_data(show_spinner=False,max_entries=8)
def report_bytes(serialized): return pdf_report(json.loads(serialized))
if st.session_state.view=='report':
    payload=build_payload()
    st.subheader('Assessment report',help='All components are included, including those with missing observations. Proposed controls remain modeled assumptions.')
    st.dataframe([{'Component':c['name'],'Impact':c['assessment']['impact'],'Exposure':c['assessment']['exposure'],'Residual':c['assessment']['residual'],'Coverage %':c['assessment']['completeness']} for c in payload['components']],hide_index=True,width='stretch')
    for limitation in payload['limitations']: st.caption(limitation)
    serialized=json.dumps(payload,indent=2)
    st.download_button('Download PDF report',report_bytes(serialized),file_name='hephaestus-assessment.pdf',mime='application/pdf')
    st.download_button('Download JSON sidecar',serialized,file_name='hephaestus-sidecar.json',mime='application/json')
    st.stop()
st.caption('01  Upload  /  02  Research  /  03  Assessment  /  04  Report')
if mode=='Offline scenario':
    st.caption('Synthetic scenario · Values are fictional; they are not repository findings.' if not upload else 'Offline inventory · Evidence has not been collected.')
else: st.caption('GitHub evidence · Verify repository mappings before relying on observations.')
coach('mapping')
with st.expander('Inventory & repository mapping',expanded=tutorial_active() and st.session_state.get('tutorial_step')==1):
    st.dataframe(components,hide_index=True,width='stretch')
    st.download_button('Download sample SBOM',raw,file_name='inventory.json',mime='application/json')
st.subheader('Research',help='Review the mappings before selecting repositories. GitHub supplies governance observations; Tavily finds public contributor sources. Research never starts on upload or rerender.')
coach('research')
repos=list(dict.fromkeys(c['repo'] for c in components if c['repo']))
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
    for index,repo in enumerate(targets):
        related=[c for c in components if c['repo']==repo]
        prior=next((evidence[c['id']] for c in related if evidence[c['id']].get('mode')=='live GitHub REST'),None)
        observation=prior or collect(repo,token,use_scorecard)
        for component in related: evidence[component['id']]=observation
        progress.progress((index+1)/len(targets),text=f'GitHub: {repo}')
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
    with col1: fetch=st.button('Fetch evidence',type='primary', help='Fetch repository metadata, branch settings, and up to 100 contributor records for this component. Other components are unchanged.')
    if fetch:
        with st.spinner('Collecting public repository evidence…'):
            evidence[selected]=collect(c['repo'],token,use_scorecard)
        st.session_state.evidence=evidence
left,right=st.columns([1.35,1])
with right:
    st.subheader('Mission & response', help='Set the consequences of this component failing or being compromised. Each input uses a 1–5 scale; higher means greater impact. Defaults are 3 and should be reviewed.')
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
coach('evidence')
t1,t2,t3=st.tabs(['Evidence','Method','Export'])
with t1:
    st.subheader(c['name']+' · '+c['version'], help='Repository observations describe the current repository, not necessarily this package release. SBOM mappings are not independently authenticated.')
    e=evidence[selected]
    st.write('Evidence origin:',e.get('mode','unknown'))
    st.caption('Retrieved: '+str(e.get('fetched_at') or 'Not a live observation'))
    if c['repo']: st.link_button('Open mapped GitHub repository','https://github.com/'+c['repo'])
    st.caption('Repository mapping: '+c['mapping'])
    st.dataframe([{'driver':k,'observed value':e.get('factors',{}).get(k),'weight':w} for k,w in __import__('core').WEIGHTS.items()],hide_index=True,width='stretch')
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
