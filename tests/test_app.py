from streamlit.testing.v1 import AppTest
from tutorial import STEPS
import json
from io import BytesIO
from pathlib import Path

def load(): return AppTest.from_file('app.py',default_timeout=30).run()
def controls(app): return next(m for m in app.multiselect if m.label=='Model mitigation controls')

def test_scenario_controls_and_component_persistence():
    app=load()
    assert not app.exception
    controls(app).select('review').run()
    assert app.metric[2].value=='65.2'
    app.slider[0].set_value(5).run()
    app.selectbox(key='component_choice').set_value('urllib3').run()
    app.selectbox(key='component_choice').set_value('requests').run()
    assert app.slider[0].value==5 and controls(app).value==['review']
    app.radio[0].set_value('Live GitHub').run()
    assert not app.exception and app.metric[1].value=='Unknown'

def test_help_report_navigation_preserves_assessment():
    app=load()
    app.slider[0].set_value(5).run()
    controls(app).select('review').run()
    app.button(key='readme_nav').click().run()
    assert not app.exception
    assert any('Quick start' in m.value for m in app.markdown)
    assert not any(m.value.startswith('# HEPHAESTUS') for m in app.markdown)
    app.button(key='back_assessment').click().run()
    assert app.slider[0].value==5 and controls(app).value==['review']
    app.button(key='finish_assessment').click().run()
    assert app.session_state.view=='report' and not app.exception
    assert len(app.get('download_button'))==2
    app.button(key='back_assessment').click().run()
    assert app.slider[0].value==5
    app.button(key='sidebar_toggle').click().run()
    assert not app.session_state.sidebar_open
    app.button(key='sidebar_toggle').click().run()
    assert app.session_state.sidebar_open

def test_tutorial_exit_cancel_and_complete():
    app=load()
    app.button(key='tutorial_nav').click().run()
    assert app.session_state.tutorial_active and len(app.metric)==4
    app.button(key='exit_tutorial').click().run()
    assert any('Are you sure' in text.value for text in app.markdown)
    app.button(key='continue_tutorial').click().run()
    assert app.session_state.tutorial_active
    app.button(key='exit_tutorial').click().run()
    app.button(key='confirm_exit_tutorial').click().run()
    assert not app.session_state.tutorial_active
    app.button(key='tutorial_nav').click().run()
    for _ in STEPS:
        assert not app.exception and len(app.metric)==4
        app.button(key='tutorial_next').click().run()
    assert not app.session_state.tutorial_active

def test_unknown_can_finish_without_network(monkeypatch):
    def forbidden(*args,**kwargs): raise AssertionError('Unexpected network request')
    monkeypatch.setattr('requests.get',forbidden)
    monkeypatch.setattr('requests.post',forbidden)
    app=load()
    app.radio[0].set_value('Live GitHub').run()
    app.button(key='finish_assessment').click().run()
    assert not app.exception and app.session_state.view=='report'

def test_spdx3_sample_runs_through_assessment_and_report():
    app=load()
    next(box for box in app.selectbox if box.label=='Sample inventory').set_value('SPDX 3').run()
    assert not app.exception and len(app.session_state.evidence)==6
    assert len(app.metric)==4
    app.button(key='finish_assessment').click().run()
    assert not app.exception and app.session_state.view=='report'

def test_upload_feedback_and_rejection_preserve_assessment(monkeypatch):
    raw = json.dumps({'sbom': json.loads(Path('samples/spdx.json').read_bytes())}).encode()
    current = {'raw': raw}
    monkeypatch.setattr('streamlit.file_uploader', lambda *args, **kwargs: BytesIO(current['raw']))
    app = load()
    assert not app.exception
    assert any('Loaded SPDX · 6 components' in item.value for item in app.success)
    assert app.metric[1].value == 'Unknown'
    app.slider[0].set_value(5).run()
    previous_context = app.session_state.context
    current['raw'] = b'{"not_an_sbom": true}'
    app.run()
    assert not app.exception and any('Valid JSON' in item.value for item in app.error)
    assert app.session_state.context == previous_context
    current['raw'] = raw
    app.run()
    assert not app.exception and app.slider[0].value == 5

def uploaded_app(monkeypatch, components):
    raw = json.dumps({'bomFormat':'CycloneDX','components':components}).encode()
    monkeypatch.setattr('streamlit.file_uploader', lambda *args, **kwargs:BytesIO(raw))
    return load()

def test_uploaded_assessment_collects_without_tavily_and_preserves_inputs(monkeypatch):
    calls=[]
    def collect(repo, *args):
        calls.append(repo)
        return {'mode':'live GitHub REST', 'factors':{'archived':0,'concentration':.8,'review':1}, 'sources':[], 'notes':[]}
    monkeypatch.setattr('evidence.collect', collect)
    monkeypatch.setattr('requests.post', lambda *a, **k:(_ for _ in ()).throw(AssertionError('Paid request')))
    app=uploaded_app(monkeypatch, [
        {'name':'one','bom-ref':'one','purl':'pkg:github/owner/shared@1'},
        {'name':'two','bom-ref':'two','purl':'pkg:github/owner/shared@2'},
        {'name':'unmapped','bom-ref':'three','purl':'pkg:pypi/unknown@1'},
    ])
    assert not app.exception and calls==[]
    assert app.metric[1].value=='Unknown' and app.metric[3].value=='0%'
    app.slider[0].set_value(5).run()
    controls(app).select('review').run()
    app.button(key='collect_assessment').click().run()
    assert not app.exception and calls==['owner/shared']
    assert app.radio[0].value=='Live GitHub'
    assert app.slider[0].value==5 and controls(app).value==['review']
    assert app.metric[0].value=='73.3' and app.metric[1].value=='70.0'
    assert app.metric[2].value=='46.8' and app.metric[3].value=='70%'
    app.selectbox(key='component_choice').set_value('two').run()
    assert app.metric[1].value=='70.0' and app.metric[3].value=='70%'
    app.button(key='collect_assessment').click().run()
    assert calls==['owner/shared']
    app.selectbox(key='component_choice').set_value('three').run()
    assert app.metric[1].value=='Unknown' and app.metric[3].value=='0%'
    assert next(b for b in app.button if b.label=='Fetch evidence').disabled
    app.button(key='finish_assessment').click().run()
    assert not app.exception and len(app.get('download_button'))==2

def test_mapping_editor_enables_collection_and_clears_stale_observations(monkeypatch):
    calls=[]
    def collect(repo, *args):
        calls.append(repo)
        return {'mode':'live GitHub REST','factors':{'archived':1},'sources':[],'notes':[]}
    monkeypatch.setattr('evidence.collect', collect)
    app=uploaded_app(monkeypatch,[{'name':'package','bom-ref':'pkg','purl':'pkg:pypi/example@1'}])
    assert app.button(key='collect_assessment').disabled
    app.slider[0].set_value(5).run()
    field=next(t for t in app.text_input if t.label=='GitHub repository (owner/repository or URL)')
    field.set_value('owner/repo').run()
    app.button(key='save_mapping').click().run()
    assert not app.exception and not app.button(key='collect_assessment').disabled and calls==[]
    app.button(key='collect_assessment').click().run()
    assert calls==['owner/repo'] and app.metric[1].value=='100.0'
    assert app.slider[0].value==5
    field=next(t for t in app.text_input if t.label=='GitHub repository (owner/repository or URL)')
    field.set_value('owner/different').run()
    app.button(key='save_mapping').click().run()
    assert not app.exception and app.metric[1].value=='Unknown'
    assert app.slider[0].value==5 and calls==['owner/repo']

def test_failed_token_can_be_retried_after_replacement(monkeypatch):
    class Response:
        def __init__(self, status, data): self.status_code, self.data=status,data
        def json(self): return self.data
    calls=[]
    def get(url, **kwargs):
        if url=='https://api.github.com/user':
            return Response(200,{'login':'example'}) if kwargs['headers'].get('Authorization')=='Bearer replacement-token' else Response(401,{})
        calls.append(url)
        if kwargs['headers'].get('Authorization')!='Bearer replacement-token': return Response(401,{})
        if '/contributors?' in url: return Response(200,[{'login':'a','contributions':7},{'login':'b','contributions':3}])
        if url.endswith('/protection'): return Response(403,{})
        if '/branches/' in url: return Response(200,{'protected':True})
        return Response(200,{'archived':False,'default_branch':'main'})
    monkeypatch.setattr('evidence.requests.get', get)
    app=uploaded_app(monkeypatch,[{'name':'one','bom-ref':'one','purl':'pkg:github/owner/repo@1'}])
    next(t for t in app.text_input if t.label=='GitHub token (optional)').set_value('expired-token').run()
    app.button(key='collect_assessment').click().run()
    assert not app.exception and app.metric[1].value=='Unknown' and app.metric[3].value=='0%'
    assert any('token invalid or expired' in m.value for m in app.markdown)
    next(t for t in app.text_input if t.label=='GitHub token (optional)').set_value('replacement-token').run()
    app.button(key='retry_assessment').click().run()
    assert not app.exception and app.metric[1].value=='46.7' and app.metric[3].value=='45%'
    assert len(calls)==6
    exported=json.dumps(app.session_state.evidence)
    assert 'expired-token' not in exported and 'replacement-token' not in exported

def test_sample_collection_preserves_requested_scope_across_mode_change(monkeypatch):
    calls=[]
    def collect(repo, *args):
        calls.append(repo)
        return {'mode':'live GitHub REST','factors':{'archived':0},'sources':[],'notes':[]}
    monkeypatch.setattr('evidence.collect', collect)
    app=load()
    next(m for m in app.multiselect if m.label=='Repositories for assessment').set_value(['psf/requests']).run()
    app.button(key='collect_assessment').click().run()
    assert not app.exception and calls==['psf/requests']
    assert next(m for m in app.multiselect if m.label=='Repositories for assessment').value==['psf/requests']
    assert not any('Session State API' in item.value for item in app.warning)

def test_immediate_credential_feedback_cache_change_and_recheck(monkeypatch):
    calls=[]
    exported=[]
    monkeypatch.setattr('reporting.pdf_report',lambda payload:exported.append(payload) or b'%PDF-1.4 test')
    class Response:
        def __init__(self,status,data): self.status_code,self.data=status,data
        def json(self): return self.data
    def get(url,**kwargs):
        calls.append((url,kwargs))
        token=kwargs['headers']['Authorization']
        if token=='Bearer bad-key': return Response(401,{})
        return Response(200,{'login':'example'} if url.endswith('/user') else {'key':{'usage':0}})
    monkeypatch.setattr('connections.requests.get',get)
    monkeypatch.setattr('requests.post',lambda *a,**k:(_ for _ in ()).throw(AssertionError('No search expected')))
    app=load()
    app.text_input(key='github_token').set_value('bad-key').run()
    assert not app.exception and any('GitHub token not accepted' in item.value for item in app.error)
    app.text_input(key='github_token').set_value('good-key').run()
    assert any('GitHub token accepted' in item.value for item in app.success)
    app.slider[0].set_value(4).run()
    assert len(calls)==2
    app.button(key='recheck_github').click().run()
    assert len(calls)==3
    app.text_input(key='tavily_api_key').set_value('tavily-secret').run()
    assert any('Tavily API key accepted' in item.value for item in app.success)
    app.text_input(key='tavily_project_id').set_value('project-secret').run()
    assert calls[-1][1]['headers']['X-Project-ID']=='project-secret'
    assert len(calls)==5 and all(url.endswith(('/user','/usage')) for url,_ in calls)
    app.text_input(key='github_token').set_value('').run()
    assert not any('GitHub token accepted' in item.value for item in app.success)
    app.button(key='finish_assessment').click().run()
    assert not app.exception
    assert all(secret not in json.dumps(exported[-1]) for secret in ['bad-key','good-key','tavily-secret','project-secret'])

def test_local_control_generation_review_staleness_and_report(monkeypatch):
    from tests.test_local_llm import proposals
    calls=[]
    def request(method,url,key='',body=None,timeout=8):
        calls.append((method,body))
        if method=='GET': return {'models':[{'name':'arbitrary-llm:7b'},{'name':'gpt-oss:20b'}]}
        return {'message':{'content':json.dumps(proposals())}}
    monkeypatch.setattr('local_llm._request',request)
    captured=[]
    monkeypatch.setattr('reporting.pdf_report',lambda payload:captured.append(payload) or b'%PDF-1.4 test')
    app=load()
    assert app.button(key='generate_controls').disabled and calls==[]
    app.button(key='connect_local_llm').click().run()
    assert not app.exception and not app.button(key='generate_controls').disabled
    assert next(box for box in app.selectbox if box.label=='Local model').value=='arbitrary-llm:7b'
    next(box for box in app.selectbox if box.label=='Local model').set_value('gpt-oss:20b').run()
    app.text_area[0].set_value('Recover within one business day.').run()
    before=[metric.value for metric in app.metric]
    app.button(key='generate_controls').click().run()
    assert not app.exception and [metric.value for metric in app.metric]==before
    assert len(calls)==2 and calls[1][0]=='POST'
    assert app.session_state.control_drafts['requests']['model']=='gpt-oss:20b'
    review=next(box for box in app.checkbox if box.label=='I have reviewed these proposed control measures')
    review.check().run()
    assert app.session_state.control_drafts['requests']['reviewed']
    app.button(key='readme_nav').click().run()
    app.button(key='back_assessment').click().run()
    assert app.text_area[0].value=='Recover within one business day.' and len(calls)==2
    app.slider[0].set_value(5).run()
    assert any('out of date' in warning.value for warning in app.warning)
    assert next(box for box in app.checkbox if box.label=='I have reviewed these proposed control measures').disabled
    app.button(key='finish_assessment').click().run()
    assert not app.exception and captured[-1]['schema'].endswith('/1.2')
    draft=captured[-1]['generated_control_measures']['requests']
    assert draft['stale'] and not draft['reviewed'] and len(draft['controls'])==1
    assert captured[-1]['components'][0]['assessment']['exposure']==81.4

def test_local_model_failure_preserves_existing_draft(monkeypatch):
    from tests.test_local_llm import proposals
    count=[]
    def request(method,*args,**kwargs):
        if method=='GET': return {'models':[{'name':'gpt-oss:20b'}]}
        count.append(1)
        if len(count)>1: raise ValueError('Local model unavailable or timed out.')
        return {'message':{'content':json.dumps(proposals())}}
    monkeypatch.setattr('local_llm._request',request)
    app=load()
    app.button(key='connect_local_llm').click().run()
    app.button(key='generate_controls').click().run()
    draft=dict(app.session_state.control_drafts['requests'])
    app.button(key='generate_controls').click().run()
    assert not app.exception and any('timed out' in error.value for error in app.error)
    assert app.session_state.control_drafts['requests']==draft

def test_manual_model_id_works_without_model_discovery(monkeypatch):
    calls=[]
    def request(method,url,key='',body=None,timeout=8):
        calls.append((method,url,body))
        if method=='GET': raise ValueError('Model discovery unavailable (HTTP 404).')
        return {'choices':[{'text':'Use a supported release and test the rollback procedure.'}]}
    monkeypatch.setattr('local_llm._request',request)
    app=load()
    app.selectbox(key='local_llm_provider').set_value('OpenAI-compatible text').run()
    app.text_input(key='local_model_override').set_value('custom-model-identifier').run()
    assert not app.button(key='generate_controls').disabled
    app.button(key='connect_local_llm').click().run()
    assert any('discovery unavailable' in error.value for error in app.error)
    app.button(key='generate_controls').click().run()
    assert not app.exception
    assert calls[-1][1].endswith('/v1/completions')
    assert calls[-1][2]['model']=='custom-model-identifier'
    draft=app.session_state.control_drafts['requests']
    assert draft['format']=='text' and 'rollback' in draft['text']
