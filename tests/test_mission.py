from copy import deepcopy
import pytest
from core import parse_sbom, score
from dependencies import reach_for_count
from mission import assign, initialize, undo


def inventory(edges=None):
    data={'bomFormat':'CycloneDX','components':[{'bom-ref':x,'name':x} for x in 'abcd']}
    if edges is not None: data['dependencies']=[{'ref':a,'dependsOn':b} for a,b in edges]
    return parse_sbom(data)[1]


@pytest.mark.parametrize('count,reach',[(0,1),(1,1),(2,2),(4,2),(5,3),(9,3),(10,4),(24,4),(25,5),(999,5)])
def test_reach_boundaries(count,reach): assert reach_for_count(count)==reach


def test_chain_cycle_shared_edges_and_missing_graph():
    items=inventory([('a',['b','b']),('b',['c']),('c',['b']),('d',[])])
    assert [c['dependency']['dependent_count'] for c in items]==[0,2,2,0]
    assert items[0]['dependency']['depends_on']==['b']
    assert all(c['dependency']['dependent_count'] is None for c in inventory())
    assert [c['dependency']['dependent_count'] for c in inventory([(x,[]) for x in 'abcd'])]==[0,0,0,0]


def test_overrides_undo_and_exposure_unchanged():
    items=inventory([('a',['b']),('b',['c']),('c',[])])
    assessments={}
    initialize(items,assessments)
    assessments['b']['inputs'][0]=5
    assessments['b']['input_sources'][0]='manual'
    before=deepcopy(assessments)
    old=assign(items,assessments,criticality=2,recovery=4,fallback=3)
    assert assessments['b']['inputs']==[5,1,4]
    assert assessments['c']['inputs']==[2,2,4]
    assert assessments['d']['inputs']==[2,3,4]
    assert assessments['d']['input_sources'][1]=='fallback'
    observation={'factors':{'archived':1,'review':1}}
    assert score(observation,before['c']['inputs'])['exposure']==score(observation,assessments['c']['inputs'])['exposure']
    assessments['b']['controls']=['review']
    undo(assessments,old)
    assert assessments['b']['inputs']==before['b']['inputs'] and assessments['b']['controls']==['review']
    assign(items,assessments,criticality=2,replace=True)
    assert assessments['b']['inputs'][0]==2


def test_legacy_inputs_are_preserved():
    items=inventory()
    assessments={'a':{'inputs':[5,4,2],'controls':['review']}}
    assign(items,assessments)
    assert assessments['a']['inputs']==[5,4,2]


def test_spdx2_reverse_relationships_not_containment():
    data={'spdxVersion':'SPDX-2.3','packages':[{'SPDXID':x,'name':x} for x in 'abc'],
          'relationships':[{'spdxElementId':'a','relatedSpdxElement':'b','relationshipType':'DEPENDS_ON'},
                           {'spdxElementId':'c','relatedSpdxElement':'b','relationshipType':'RUNTIME_DEPENDENCY_OF'},
                           {'spdxElementId':'c','relatedSpdxElement':'a','relationshipType':'CONTAINS'}]}
    items=parse_sbom(data)[1]
    assert [c['dependency']['dependent_count'] for c in items]==[0,1,2]


@pytest.mark.parametrize('expanded',[False,True])
def test_spdx3_graph_edges_expanded_compact_and_split(expanded):
    core='https://spdx.org/rdf/3.0.1/terms/Core/'
    sw='https://spdx.org/rdf/3.0.1/terms/Software/'
    prop=lambda x:core+x if expanded else x
    nodes=[{'@id':x,'@type':sw+'Package','name':x} for x in 'abc']
    nodes += [{'spdxId':'rel','type':'Relationship',prop('relationshipType'):core+'dependsOn' if expanded else 'dependsOn',prop('from'):{'@id':'a'}},
              {'@id':'rel',prop('to'):[{'@id':'b'},{'@id':'c'}]},
              {'type':'Relationship','relationshipType':'contains','from':'b','to':['a']}]
    items=parse_sbom({'@graph':nodes})[1]
    assert [c['dependency']['dependent_count'] for c in items]==[0,1,1]


def test_duplicate_ids_dangling_refs_no_network(monkeypatch):
    monkeypatch.setattr('requests.get',lambda *a,**k:pytest.fail('Network during graph parse'))
    data={'bomFormat':'CycloneDX','components':[{'name':x,'bom-ref':x} for x in ['a','b','b','c']],
          'dependencies':[{'ref':'a','dependsOn':['b','missing','c']}]}
    _,items,warnings=parse_sbom(data)
    assert items[-1]['dependency']['dependent_count']==1
    assert items[1]['dependency']['dependent_count'] is None
    assert any('ignored' in warning for warning in warnings)
