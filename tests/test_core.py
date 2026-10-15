import json
from pathlib import Path
import pytest
from core import parse_sbom, read_sbom, repository, repository_input, score, sidecar, report
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

def test_mapping_input_and_duplicate_ids_remain_distinct():
    assert repository_input(' owner/repo ')=='owner/repo'
    assert repository_input('https://github.com/owner/repo.git')=='owner/repo'
    assert repository_input('') is None
    for value in ['../repo','owner/..','https://example.org/owner/repo','https://[invalid']:
        with pytest.raises(ValueError): repository_input(value)
    _, components, _=parse_sbom({'bomFormat':'CycloneDX','components':[
        {'name':'one','bom-ref':'x'}, {'name':'two','bom-ref':'x#3'},
        {'name':'three','bom-ref':'x'}, {'name':'four','bom-ref':'x#3'}]})
    assert len({component['id'] for component in components})==4

@pytest.mark.parametrize('name', ['cyclonedx', 'spdx', 'spdx3'])
def test_wrapped_sbom_preserves_components(name):
    data = json.loads(Path('samples/'+name+'.json').read_bytes())
    expected_format, expected_components, _ = parse_sbom(data)
    fmt, items, warnings = read_sbom(json.dumps({'sbom': data}).encode())
    assert fmt == expected_format and items == expected_components
    assert warnings == ['Read the inventory from the JSON sbom wrapper.']

@pytest.mark.parametrize(('raw', 'message'), [
    (b'  ', 'file is empty'),
    (b'{\n "components": [}', 'line 2, column 17'),
    (b'\xff\xfe\xff', 'UTF-8'),
    (b'{}', 'Valid JSON, but its SBOM format was not recognized'),
    (b'"quoted JSON"', 'quoted JSON string'),
    (b' ' * (10 * 1024 * 1024 + 1), '10 MB'),
], ids=['empty', 'syntax', 'encoding', 'unsupported', 'quoted', 'size'])
def test_upload_error_explains_failure(raw, message):
    with pytest.raises(ValueError, match=message): read_sbom(raw)

def test_upload_accepts_utf8_bom():
    raw = b'\xef\xbb\xbf' + Path('samples/spdx.json').read_bytes()
    fmt, items, warnings = read_sbom(raw)
    assert fmt == 'SPDX' and len(items) == 6 and not warnings

@pytest.mark.parametrize('data', [
    {'bomFormat': 'CycloneDX', 'components': [{'name': 'component', 'externalReferences': [{'url': 'https://[invalid'}, {'url': 'https://github.com/owner/repo'}]}]},
    {'spdxVersion': 'SPDX-2.3', 'packages': [{'name': 'component', 'externalRefs': [{'referenceLocator': 'https://[invalid'}, {'referenceLocator': 'https://github.com/owner/repo'}]}]},
])
def test_malformed_mapping_keeps_inventory(data):
    _, items, warnings = parse_sbom(data)
    assert len(items) == 1 and items[0]['repo'] == 'owner/repo'
    assert any('malformed repository URL ignored' in warning for warning in warnings)

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
