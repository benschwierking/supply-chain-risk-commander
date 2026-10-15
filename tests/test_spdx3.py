import json
from pathlib import Path
import pytest
from core import parse_sbom, sidecar, score

CONTEXT='https://spdx.org/rdf/3.0.1/spdx-context.jsonld'
CORE='https://spdx.org/rdf/3.0.1/terms/Core/'
SW='https://spdx.org/rdf/3.0.1/terms/Software/'

def graph(*nodes,context=CONTEXT): return {'@context':context,'@graph':list(nodes)}
def package(**fields): return {'type':'software_Package','spdxId':'https://example.org/package','name':'component',**fields}

def test_bundled_graph_inventory_and_sidecar():
    fmt,items,warnings=parse_sbom(json.loads(Path('samples/spdx3.json').read_text()))
    assert fmt=='SPDX 3' and len(items)==6 and not warnings
    assert items[0]['repo']=='psf/requests' and items[0]['purl']=='pkg:pypi/requests@2.32.5'
    assert items[0]['version']=='2.32.5' and items[0]['id'].endswith('/requests')
    results={c['id']:score({},[3,3,3]) for c in items}
    payload=sidecar(items,{},results,'test')
    assert payload['component_repository_map'][items[0]['id']]=='psf/requests'

@pytest.mark.parametrize('wrapped',[True,False])
def test_expanded_jsonld_graph(wrapped):
    nodes=[{'@type':[SW+'Package'],'@id':'https://example.org/pkg',CORE+'name':[{'@value':'Expanded'}],
           SW+'packageVersion':[{'@value':'3.1'}],SW+'packageUrl':[{'@value':'pkg:github/owner/repo@3.1'}],
           CORE+'externalRef':[{'@id':'_:ref'}]},
           {'@type':[CORE+'ExternalRef'],'@id':'_:ref',CORE+'locator':[{'@value':'https://github.com/owner/repo'}]},
           {'@type':[SW+'File'],'@id':'https://example.org/file',CORE+'name':[{'@value':'not a package'}]}]
    _,items,warnings=parse_sbom(graph(*nodes) if wrapped else nodes)
    assert len(items)==1 and items[0]['name']=='Expanded' and items[0]['version']=='3.1'
    assert items[0]['repo']=='owner/repo' and not warnings


def test_inline_references_prefixes_and_literals():
    data=graph({'@type':'sw:Package','spdxId':'doc:pkg','c:name':'Namespaced','sw:packageVersion':'1',
                'c:externalRef':[{'@id':'doc:ref'}],
                'c:externalIdentifier':[{'type':'ExternalIdentifier','identifier':'pkg:pypi/namespaced@1'}]},
               {'@id':'doc:ref','c:locator':['git+https://github.com/owner/repo.git']},
               context=[CONTEXT,{'sw':SW,'c':CORE,'doc':'https://example.org/'}])
    _,items,warnings=parse_sbom(data)
    assert items[0]['id']=='https://example.org/pkg' and items[0]['repo']=='owner/repo'
    assert items[0]['purl']=='pkg:pypi/namespaced@1' and not warnings


def test_split_descriptions_merge_and_conflicts_stay_unknown():
    data=graph(package(software_packageVersion='1'),{'spdxId':'https://example.org/package','software_packageVersion':'2'},
               {'spdxId':'https://example.org/package','externalRef':[{'locator':['https://github.com/a/b','https://github.com/c/d']} ]})
    _,items,warnings=parse_sbom(data)
    assert len(items)==1 and items[0]['version']=='unknown' and items[0]['repo'] is None
    assert len(warnings)==2


def test_unresolved_references_missing_id_and_malformed_node():
    data=graph({'type':['software_Package'],'name':'Unmapped','externalRef':['_:missing'],
                'externalIdentifier':[123]},None)
    _,items,warnings=parse_sbom(data)
    assert items[0]['repo'] is None and items[0]['version']=='unknown' and items[0]['id'].startswith('component-spdx3-')
    assert any('unresolved' in w for w in warnings) and any('malformed' in w for w in warnings)


def test_nonpackage_and_foreign_type_are_not_inventory():
    for node in [{'type':'Person','name':'a'}, {'@type':'https://evil.test/Software/Package'}, {'type':'software_File'}]:
        with pytest.raises(ValueError,match='No SPDX 3'): parse_sbom(graph(node))

@pytest.mark.parametrize('value',[{'@graph':{}},{'@graph':None},{'@graph':[]},{'@graph':[{'@graph':{}}]}])
def test_invalid_graph_errors(value):
    with pytest.raises(ValueError): parse_sbom(value)


def test_graph_package_limit():
    data=graph(*[package(spdxId=f'https://example.org/pkg{i}') for i in range(1001)])
    with pytest.raises(ValueError,match='1,000'): parse_sbom(data)


def test_no_network_context_or_external_resolution(monkeypatch):
    def forbidden(*args,**kwargs): raise AssertionError('Parser attempted network access')
    monkeypatch.setattr('requests.get',forbidden)
    _,items,w=parse_sbom(graph(package(externalRef=['https://example.org/remote']),context='https://example.org/remote-context'))
    assert items[0]['repo'] is None and any('not fetched' in warning for warning in w)


def test_different_context_urls_and_inline_vocabulary():
    for version in ['3','3.0','3.0.1','3.1']:
        sw=f'https://spdx.org/rdf/{version}/terms/Software/'
        _,items,_=parse_sbom(graph({'@type':sw+'Package','@id':'urn:pkg',CORE+'name':'Context-free','packageUrl':'pkg:github/o/r'}, context={'@vocab':sw}))
        assert items[0]['repo']=='o/r'


def test_typed_local_reference_and_split_external_nodes():
    _,items,w=parse_sbom(graph(package(externalRef=[{'@id':'_:ref','@type':CORE+'ExternalRef'}]),
                                {'@id':'_:ref','locator':'https://github.com/o/r'}))
    assert items[0]['repo']=='o/r' and not w


def test_malformed_url_does_not_discard_component():
    _,items,w=parse_sbom(graph(package(software_homePage='https://[invalid',software_packageUrl='pkg:pypi/example@1')))
    assert items[0]['name']=='component' and items[0]['repo'] is None
    assert any('malformed repository' in warning for warning in w)
