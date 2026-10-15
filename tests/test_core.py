import json
from pathlib import Path
import pytest
from core import parse_sbom, repository, score, sidecar, report
from evidence import collect

@pytest.mark.parametrize('name',['cyclonedx','spdx'])
def test_samples(name):
    fmt,items,warnings=parse_sbom(json.loads(Path('samples/'+name+'.json').read_text()))
    assert len(items)==6 and items[0]['repo']=='psf/requests' and not warnings

def test_nested_duplicates_and_missing():
    _,items,w=parse_sbom({'bomFormat':'CycloneDX','components':[{'name':'a','bom-ref':'x','components':[{'name':'b','bom-ref':'x'}]},None]})
    assert len({i['id'] for i in items})==2 and len(w)==2 and items[1]['repo'] is None

@pytest.mark.parametrize('value',[[],{}, {'spdxVersion':'SPDX-3.0'}, {'bomFormat':'CycloneDX','components':{}}])
def test_invalid(value):
    with pytest.raises(ValueError): parse_sbom(value)

def test_mapping():
    assert repository('git+https://github.com/psf/requests.git')=='psf/requests'
    assert repository('pkg:github/psf/requests@v1')=='psf/requests'
    assert repository('https://github.com.attacker.test/psf/requests') is None
    assert repository('https://example.org/github.com/psf/requests') is None

def test_unknown_and_mitigation():
    unknown=score({},[3,3,3],['review'])
    assert unknown['exposure'] is None and unknown['completeness']==0
    e={'factors':{'review':1,'archived':0}}
    before=score(e,[5,5,5]); after=score(e,[5,5,5],['review'])
    assert before['exposure']==62.5 and after['residual']==21.9
    assert before['completeness']==after['completeness']==40 and after['impact']==100
    assert score(e,[1,1,1],['review','review'])==score(e,[1,1,1],['review','review'])

def test_export_roundtrip():
    c=[{'id':'x','name':'a','version':'1','repo':None}]; e={'x':{'factors':{}}}; s={'x':score(e['x'],[3,3,3])}
    p=json.loads(json.dumps(sidecar(c,e,s,'test')))
    assert p['components'][0]['assessment']['exposure'] is None
    assert 'not probability' in report(p) and 'None' in report(p)

def test_rate_limit(monkeypatch):
    class Response:
        status_code=403
    monkeypatch.setattr('evidence.requests.get',lambda *a,**kw:Response())
    e=collect('psf/requests','secret')
    assert not e['factors'] and len(e['sources'])==2 and 'secret' not in json.dumps(e)

def test_live_partial_evidence(monkeypatch):
    class Response:
        status_code=200
        def __init__(self,value): self.value=value
        def json(self): return self.value
    def request(url,**kw):
        if '/contributors?' in url: return Response([{'login':'a','contributions':8},{'login':'b','contributions':2}])
        if url.endswith('/protection'): return Response({'required_pull_request_reviews':{'required_approving_review_count':1}})
        if '/branches/' in url: return Response({'protected':True})
        return Response({'archived':False,'default_branch':'main'})
    monkeypatch.setattr('evidence.requests.get',request)
    e=collect('org/repo')
    assert e['factors']=={'archived':0,'review':0,'concentration':.8}
    assert 'branch' not in e['factors']
