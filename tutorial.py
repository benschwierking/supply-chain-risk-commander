"""Guidance rendered beside the real controls; no network side effects."""
import streamlit as st

STEPS=[
 ('inventory','Choose an inventory','Use a sample to learn without uploading, or import CycloneDX/SPDX JSON. The file identifies packages and repository mappings; it does not prove their security.'),
 ('mapping','Check repository mappings','Confirm that each package points to its actual upstream repository. Researching the wrong repository produces irrelevant observations. Unmapped packages stay unknown.'),
 ('connections','Choose evidence and connections','Offline sample values are fictional. Live GitHub provides repository observations. A GitHub token is optional; Tavily requires its own key for public-source research. Keys stay in this session. Neither tutorial navigation nor upload starts paid searches.'),
 ('research','Set a research scope','Choose up to five verified repositories and 1–3 contributors each. Two searches per contributor means at most 30 Tavily searches per run. Run research explicitly; cached results are reused. Missing sources are not negative findings.'),
 ('component','Inspect a component','Select a package here or click its matrix point. In Live GitHub mode, Fetch evidence collects the governance observations used by the score. Web research stays separate from that score.'),
 ('criticality','Set operational criticality','How essential is the component? 1: optional convenience; 2: minor degradation; 3: important function degraded; 4: core operation disrupted; 5: mission cannot continue. Choose based on your operation, not package popularity.'),
 ('reach','Set deployment reach','How far could impact spread? 1: isolated test/user; 2: small service; 3: several services/team; 4: multiple teams or production systems; 5: organization-wide or critical shared infrastructure.'),
 ('recovery','Set recovery difficulty','How hard is recovery or replacement? 1: immediate rollback; 2: hours; 3: coordinated work over days; 4: major migration over weeks; 5: no practical replacement or prolonged loss. Higher values increase mission impact.'),
 ('matrix','Read impact, exposure and coverage','Horizontal position is mission impact; vertical is observed exposure. Circles are baseline, diamonds modeled residual. Larger points have more evidence coverage. Low exposure with missing evidence cannot establish low overall exposure. Unknown components remain selectable.'),
 ('controls','Compare proposed controls','Select safeguards to explore illustrative reductions. These choices do not implement settings or prove compliance. Review the OSPS references and assumed effects before planning changes.'),
 ('evidence','Review the sources','Read timestamps, API status, contributor samples, source links, and heuristic research matches. Confirm source identity yourself. No matches or failed searches do not imply malicious intent. Identity and U.S. Person status stay unverified.'),
 ('finish','Finish and download','Finish assessment opens a report preview with PDF and JSON downloads. All components, missing evidence, source provenance, and modeled controls are included. Obtain mission-owner review before an operational decision.')
]

def active(): return st.session_state.get('tutorial_active',False)
def start():
    st.session_state.sidebar_open=True
    st.session_state.tutorial_exit_requested=False
    st.session_state.tutorial_active=True
    st.session_state.tutorial_step=0
    st.session_state.view='assessment'
def advance():
    if st.session_state.tutorial_step>=len(STEPS)-1:
        st.session_state.tutorial_active=False
    else: st.session_state.tutorial_step+=1
@st.dialog('Exit tutorial')
def confirm_exit():
    st.write('Are you sure you want to exit from the tutorial?')
    if st.button('Continue tutorial',key='continue_tutorial'):
        st.session_state.tutorial_exit_requested=False
        st.rerun()
    if st.button('Exit tutorial',key='confirm_exit_tutorial'):
        st.session_state.tutorial_active=False
        st.session_state.tutorial_exit_requested=False
        st.session_state.view='assessment'
        st.rerun()
def coach(section):
    if not active(): return
    index=st.session_state.get('tutorial_step',0)
    target,title,body=STEPS[index]
    if target!=section: return
    with st.container(key='tutorial_card_'+section,border=True):
        st.caption(f'Tutorial · {index+1} / {len(STEPS)}')
        st.markdown('**'+title+'**')
        st.write(body)
        st.button('Finish tutorial' if index==len(STEPS)-1 else 'Next',key='tutorial_next',on_click=advance)
        if st.button('Exit tutorial',key='exit_tutorial'):
            st.session_state.tutorial_exit_requested=True
        if st.session_state.get('tutorial_exit_requested',False): confirm_exit()
    # A tiny local component scrolls the active card into view without changing page state.
    from streamlit.components.v1 import html
    html('''<script>
    const selector = '.st-key-tutorial_card_'''+section+''', [class*="st-key-tutorial_card_'''+section+'''"]';
    let attempts=0;
    const timer=setInterval(()=>{
      try {
        const card=window.parent.document.querySelector(selector);
        if(card){card.scrollIntoView({behavior:'smooth',block:'center'});clearInterval(timer);}
      } catch(e){clearInterval(timer);}
      if(++attempts>10)clearInterval(timer);
    },100);
    </script>''',height=0)
