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
