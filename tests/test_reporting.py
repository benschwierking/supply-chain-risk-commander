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
    assert result.startswith(b'%PDF') and len(result)>5000
    decoded=json.loads(json.dumps(payload))
    assert decoded['component_repository_map'][components[0]['id']]=='psf/requests'
    assert decoded['contributor_research']==research
    assert len(decoded['components'])==len(components)
