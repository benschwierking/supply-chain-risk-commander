import json
from pathlib import Path
import pytest
from core import parse_sbom, score, sidecar
from evidence import synthetic
from reporting import pdf_report

@pytest.mark.parametrize('mode',['synthetic','unknown','live','partial'])
def test_pdf_and_json_with_all_evidence_modes(mode):
    _,components,_=parse_sbom(json.loads(Path('samples/cyclonedx.json').read_text()))
    evidence={c['id']:synthetic(i) if mode=='synthetic' else {'mode':mode,'factors':{} if mode=='unknown' else {'archived':0},'notes':['Partial evidence <requires> review & validation'],'sources':[{'url':'https://api.github.com/repos/a/b','http_status':200}]} for i,c in enumerate(components)}
    components[0]['name']='Long component name '+('abcdefghij-'*30)
    assessments={c['id']:score(evidence[c['id']],[3,3,3]) for c in components}
    research={'psf/requests:3':{'repository':'psf/requests','status':mode,'upstream_revision':'test','retrieved_at':'2026-10-15','contributors':[{'login':'alice','outcome':'Heuristic probable match','queries':['"alice" repo'],'sources':[{'title':'Source <unsafe> & title','url':'https://example.org/source','heuristic_match':'probable','excerpt':'Evidence excerpt '*90}]}]}}
    payload=sidecar(components,evidence,assessments,mode,research)
    payload['sbom_sha256']='a'*64
    payload['generated_control_measures']={
        components[0]['id']:{'provider':'Ollama','model':'any-model','generated_at':'2026-10-15','reviewed':False,'stale':mode=='partial',
                             'controls':[{'id':1,'title':'Verify <review> & recovery','priority':'High','rationale':'Unknown safeguard '*60,
                                          'actions':['Assign an authorized reviewer.','Record a rollback exercise.'],
                                          'verification':'Inspect the evidence and record approval.','source_urls':[payload['baseline']]}]},
        components[1]['id']:{'provider':'OpenAI-compatible text','model':'another-model','generated_at':'2026-10-15','reviewed':True,'stale':False,
                             'controls':[],'text':'Unstructured draft <requires> human review.\n\n'+('Document recovery procedures and verify the result. '*100)}
    }
    result=pdf_report(payload)
    assert result.startswith(b'%PDF') and result.endswith(b'%%EOF\n')
    decoded=json.loads(json.dumps(payload))
    assert decoded['component_repository_map'][components[0]['id']]=='psf/requests'
    assert decoded['contributor_research']==research
    assert len(decoded['components'])==len(components)


def compact_payload(size=12,unknown=False):
    from evidence import synthetic
    components=[{'id':f'component-{i:03}','name':f'Package {i:03}','version':'1','repo':'example/project'} for i in range(size)]
    observations={c['id']:{} if unknown else synthetic(i) for i,c in enumerate(components)}
    assessments={c['id']:score(observations[c['id']],[3,3,3],['review'] if i==size-1 else []) for i,c in enumerate(components)}
    payload=sidecar(components,observations,assessments,'test')
    payload['generated_control_measures']={}
    return payload


def test_compact_pdf_has_three_sections_checked_actions_only_and_links():
    from io import BytesIO
    from pypdf import PdfReader
    from control_plan import priorities
    payload=compact_payload()
    last=payload['components'][-1]
    payload['generated_control_measures'][last['id']]={'stale':False,'controls':[
        {'title':'SELECTED ACTION','actions':['Perform this exact action.'],'selected':True,'source_urls':['https://example.org/evidence']},
        {'title':'UNCHECKED ACTION','actions':['Do not export this draft.'],'selected':False}]}
    payload['generated_control_measures'][payload['components'][0]['id']]={'stale':True,'controls':[
        {'title':'STALE ACTION','actions':['Old context.'],'selected':True}]}
    reader=PdfReader(BytesIO(pdf_report(payload)))
    text='\n'.join(page.extract_text() for page in reader.pages)
    assert all(label in text for label in ['Mission exposure matrix','Ten highest-priority components','Selected implementation plan','SELECTED ACTION','Package 011'])
    assert 'UNCHECKED ACTION' not in text and 'STALE ACTION' not in text and 'Contributor source research' not in text
    assert len(priorities(payload))==10 and len(reader.pages)<=3
    links=[a.get_object().get('/A',{}).get('/URI') for page in reader.pages for a in page.get('/Annots',[])]
    assert 'https://example.org/evidence' in links


def test_unknown_pdf_and_large_selected_component_mapping_paginate():
    from io import BytesIO
    from pypdf import PdfReader
    payload=compact_payload(1000,True)
    for component in payload['components']:
        component['assessment']['selected_controls']=['review']
    payload['components'][0]['name']='Long component '+'abcdefghij-'*80
    reader=PdfReader(BytesIO(pdf_report(payload)))
    text='\n'.join(page.extract_text() for page in reader.pages)
    assert 'No components have scored evidence yet.' in text
    assert '1000 component(s) with unknown exposure' in text
    assert all(f'Package {i:03}' in text for i in range(1,1000))
    assert len(reader.pages)>2
    empty=compact_payload(2,True)
    for c in empty['components']: c['assessment']['selected_controls']=[]
    text=PdfReader(BytesIO(pdf_report(empty))).pages[0].extract_text()
    assert 'No controls selected for implementation' in text
