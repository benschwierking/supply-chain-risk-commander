from streamlit.testing.v1 import AppTest
from tutorial import STEPS

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
