"""Guidance rendered beside the real controls; no network side effects."""
import streamlit as st

STEPS=[
 ('inventory','Choose an inventory','Use a sample to learn without uploading, or use Import an SBOM in the sidebar to load your own CycloneDX/SPDX JSON (including SPDX 3 JSON-LD graphs). The bundled-sample notice and Download sample SBOM identify an example inventory. After upload, check the loaded component count. The file identifies packages and repository mappings; it does not prove their security.'),
 ('mapping','Fill missing repository mappings','Click Auto-map all components to find and apply unambiguous repositories across the whole inventory. It handles batches for you and preserves existing mappings. Public registries receive package names and versions without API keys. The results show how many were added and which remain unresolved. Expand Mapping details and manual choices only to inspect sources, resolve ambiguity, or correct a mapping. Automatic mappings are labeled unverified; they do not supply score observations. Continue to Collect all GitHub evidence.'),
 ('connections','Choose evidence and connections','Offline sample values are fictional. Enter a token or API key, then press Enter or leave the field: accepted, rejected, or unverified feedback appears beside it. Recheck retries without running searches. A GitHub token is optional; accepted credentials may still lack access to particular settings. Tavily has a separate key for optional web research. Keys stay in this session. Collect all GitHub evidence gathers score observations from GitHub.'),
 ('assessment_collection','Collect score observations','Click Collect all GitHub evidence to process every mapped repository. Shared repositories are collected once and previous results are reused. Stop and Resume preserve progress; rate limits pause the queue. Advanced selection can limit the scope. This action uses GitHub without Tavily credits. Retry missing evidence after correcting access or network failures. Unknowns mean no supporting observations; they do not mean zero exposure.'),
 ('research','Set a research scope','Choose up to five verified repositories and 1–3 contributors each. Two searches per contributor means at most 30 Tavily searches per run. Run research explicitly; cached results are reused. Missing sources are not negative findings.'),
 ('mission_assignment','Assign mission impact quickly','Set criticality and recovery once, then Auto-assign mission impact. Recorded dependent counts estimate reach: 0–1 / 2–4 / 5–9 / 10–24 / 25+ map to 1 / 2 / 3 / 4 / 5. Missing graphs use fallback reach. This is a heuristic, not measured deployment. Manual edits are preserved unless you replace overrides; Undo restores the previous inputs.'),
 ('component','Inspect a component','Select a package here or click its matrix point. Collect all GitHub evidence fills the exposure and coverage values from GitHub observations. Component assessment status shows what is missing; Retry missing evidence retries failed collections. Fetch evidence refreshes this repository. Mission impact starts at 60 until you change the three mission scales. Web research stays separate from the score.'),
 ('criticality','Set operational criticality','How essential is the component? 1: optional convenience; 2: minor degradation; 3: important function degraded; 4: core operation disrupted; 5: mission cannot continue. Choose based on your operation, not package popularity.'),
 ('reach','Set deployment reach','How far could impact spread? 1: isolated test/user; 2: small service; 3: several services/team; 4: multiple teams or production systems; 5: organization-wide or critical shared infrastructure.'),
 ('recovery','Set recovery difficulty','How hard is recovery or replacement? 1: immediate rollback; 2: hours; 3: coordinated work over days; 4: major migration over weeks; 5: no practical replacement or prolonged loss. Higher values increase mission impact.'),
 ('matrix','Read impact, exposure and coverage','Horizontal position is mission impact; vertical is observed exposure. Red circles are before controls; green diamonds are modeled after controls. Numbered points correspond to the priority report. Low exposure with missing evidence cannot establish low overall exposure. Unknown components remain selectable.'),
 ('controls','Compare proposed controls','All control choices live here, below the assessment. Check built-in safeguards or individual generated actions to include them in your implementation plan. Select all and Clear selection apply to the displayed component. Only checked current controls enter the PDF. Built-in effects are illustrative; generated actions do not change scores. Selection does not prove implementation.'),
 ('local_controls','Draft control measures locally','Start your chosen local model server. In Local LLM connection, select its API protocol, connect, and choose a model; use Model ID override if discovery is unavailable. Review the context preview and add operational constraints before Generate control measures. Structured and plain-text drafts are supported. The proposals do not change scores. Review each action and check Include in implementation plan beside the ones you want. Plain-text actions can be edited or added as cards. Changed mission inputs or evidence make drafts stale and clear selections; regeneration starts unchecked. JSON retains every draft and its selection status.'),
 ('evidence','Review the sources','Read timestamps, API status, contributor samples, source links, and heuristic research matches. Confirm source identity yourself. No matches or failed searches do not imply malicious intent. Identity and U.S. Person status stay unverified.'),
 ('finish','Finish and download','Finish assessment opens a report preview with PDF and JSON downloads. The PDF contains a red/green matrix, ten priority components ranked by impact times exposure, and only checked controls with component assignments. Unknown exposure is counted separately. Full evidence, all drafts, and provenance remain in JSON. Obtain mission-owner review before an operational decision.')
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
