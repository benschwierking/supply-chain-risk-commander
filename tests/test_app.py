from streamlit.testing.v1 import AppTest

def test_scenario_controls_and_component_persistence():
    app=AppTest.from_file('app.py',default_timeout=30).run()
    assert not app.exception
    app.multiselect[0].select('review').run()
    assert app.metric[2].value=='65.2'
    app.slider[0].set_value(5).run()
    app.selectbox(key='component_choice').set_value('urllib3').run()
    app.selectbox(key='component_choice').set_value('requests').run()
    assert app.slider[0].value==5 and app.multiselect[0].value==['review']
    app.radio[0].set_value('Live GitHub').run()
    assert not app.exception and app.metric[1].value=='Unknown'

def test_help_navigation_preserves_assessment():
    app=AppTest.from_file('app.py',default_timeout=30).run()
    app.slider[0].set_value(5).run()
    app.radio(key='page').set_value('README').run()
    assert not app.exception
    assert any('Quick start' in m.value for m in app.markdown)
    app.radio(key='page').set_value('Tutorial').run()
    next(b for b in app.button if b.label=='Next').click().run()
    assert app.session_state.tutorial_step==1
    next(b for b in app.button if b.label=='Open assessment').click().run()
    assert app.slider[0].value==5 and len(app.metric)==4
    app.button(key='sidebar_toggle').click().run()
    assert not app.session_state.sidebar_open
    app.button(key='sidebar_toggle').click().run()
    assert app.session_state.sidebar_open
