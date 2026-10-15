import json
import pytest
import requests

from core import score
from evidence import unknown_evidence
from mapping import (MAX_LOOKUPS, MAX_BYTES, TIMEOUT, package_ref, lookup_plan,
                     lookup_repository, lookup_batch, pending_lookups, candidate_options, apply_candidates, auto_map_all)


class Response:
    def __init__(self, data, status=200):
        self.raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.status_code = status
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def iter_content(self, size): yield self.raw


def registry(monkeypatch, response):
    calls = []
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            assert self.trust_env is False
            if isinstance(response, Exception): raise response
            return response
    monkeypatch.setattr('mapping.requests.Session', Session)
    return calls


@pytest.mark.parametrize('purl,url', [
    ('pkg:pypi/Foo_Bar@1.2', 'https://pypi.org/pypi/foo-bar/1.2/json'),
    ('pkg:npm/%40scope/name@1.2.3', 'https://registry.npmjs.org/@scope%2Fname/1.2.3'),
    ('pkg:npm/@scope/name', 'https://registry.npmjs.org/@scope%2Fname/latest'),
    ('pkg:maven/org.example/library@1.2?repository_url=https://private.example', 'https://repo.maven.apache.org/maven2/org/example/library/1.2/library-1.2.pom'),
])
def test_fixed_registry_plans(purl, url):
    assert lookup_plan(purl)['url'] == url


def test_pypi_identity_normalization_and_qualifier_deduplication():
    assert package_ref('pkg:pypi/Foo_Bar@1?arch=any')['key'] == package_ref('pkg:pypi/foo-bar@1#folder')['key']


@pytest.mark.parametrize('purl', ['pkg', None, 'pkg:pypi/..@1', 'pkg:pypi/%2e%2e@1', 'pkg:pypi/a%2fb@1', 'pkg:maven/a/b', 'pkg:deb/debian/package@1', 'pkg:golang/example.org/private@1'])
def test_unsupported_or_malformed_never_requests(monkeypatch, purl):
    def forbidden(*args, **kwargs): raise AssertionError('Unexpected request')
    monkeypatch.setattr('mapping.requests.Session', forbidden)
    assert lookup_repository(purl)['status'] == 'unsupported'


def test_golang_path_candidate_has_no_request(monkeypatch):
    monkeypatch.setattr('mapping.requests.Session', lambda:pytest.fail('Unexpected request'))
    result = lookup_repository('pkg:golang/github.com/acme/library/v2@v2.3.0')
    assert result['candidates'][0]['repository'] == 'acme/library'
    assert result['source_url'] is None


def test_pypi_conflicting_sources_preserved_and_credentials_excluded(monkeypatch):
    monkeypatch.setenv('GITHUB_TOKEN', 'github-secret')
    monkeypatch.setenv('TAVILY_API_KEY', 'tavily-secret')
    calls = registry(monkeypatch, Response({'info': {'project_urls': {
        'Source': 'https://github.com/acme/project', 'Repository': 'https://github.com/other/project',
        'Funding': 'https://github.com/sponsors/someone', 'Code': 'https://user:metadata-secret@github.com/private/repo'}}}))
    result = lookup_repository('pkg:pypi/project@1?token=qualifier-secret')
    assert result['status'] == 'ambiguous'
    assert {c['repository'] for c in result['candidates']} == {'acme/project', 'other/project'}
    assert calls[0][1]['timeout'] == TIMEOUT and calls[0][1]['allow_redirects'] is False
    combined = json.dumps((calls, result))
    assert all(secret not in combined for secret in ['github-secret', 'tavily-secret', 'metadata-secret', 'qualifier-secret'])


@pytest.mark.parametrize('repo', ['git+https://github.com/acme/project.git', 'github:acme/project', 'acme/project', 'git+ssh://git@github.com/acme/project.git'])
def test_npm_repository_forms(monkeypatch, repo):
    registry(monkeypatch, Response({'repository': {'url': repo}, 'homepage': 'https://github.com/unrelated/homepage'}))
    result = lookup_repository('pkg:npm/project@1')
    assert result['status'] == 'candidate' and result['candidates'][0]['repository'] == 'acme/project'


def test_maven_scm_and_no_parent_requests(monkeypatch):
    calls = registry(monkeypatch, Response(b'<?xml version="1.0" encoding="UTF-8"?><!-- Normal POM comment --><project xmlns="http://maven.apache.org/POM/4.0.0"><parent><url>https://github.com/not/a-source</url></parent><scm><connection>scm:git:git@github.com:acme/project.git</connection></scm></project>'))
    result = lookup_repository('pkg:maven/org.acme/project@1')
    assert result['status'] == 'candidate' and result['candidates'][0]['repository'] == 'acme/project'
    assert len(calls) == 1


@pytest.mark.parametrize('response,status', [
    (Response({}, 404), 'not_found'), (Response({}, 429), 'failed'), (Response({}, 302), 'failed'),
    (Response(b'<!DOCTYPE a [<!ENTITY x "value">]><project/>'), 'failed'),
    (Response(b'x' * (MAX_BYTES + 1)), 'failed'),
    (requests.Timeout('URL contains secret-error'), 'failed'),
])
def test_bounded_sanitized_failures(monkeypatch, response, status):
    registry(monkeypatch, response)
    result = lookup_repository('pkg:maven/org.example/library@1')
    assert result['status'] == status and 'secret-error' not in json.dumps(result)


def test_batch_deduplicates_limits_caches_and_only_retries_failures(monkeypatch):
    calls = []
    def lookup(purl):
        calls.append(purl)
        return {'status': 'failed' if '/bad@' in purl else 'not_found', 'candidates': []}
    monkeypatch.setattr('mapping.lookup_repository', lookup)
    cache = {}
    purls = ['pkg:pypi/bad@1'] + [f'pkg:pypi/pkg{i}@1' for i in range(220)]
    lookup_batch(purls + purls, cache)
    assert len(calls) == len(cache) == MAX_LOOKUPS
    lookup_batch(purls[:25], cache)
    assert len(calls) == MAX_LOOKUPS
    lookup_batch(purls[:25], cache, retry=True)
    assert len(calls) == MAX_LOOKUPS + 1 and calls[-1] == 'pkg:pypi/bad@1'
    components = [{'id': str(i), 'repo': None, 'purl': p} for i, p in enumerate(purls + [purls[0]])]
    assert len(pending_lookups(components, cache)) == 196
    assert len(pending_lookups(components, cache, retry=True)) == 1


def test_review_required_and_ambiguous_selection_rejected_without_side_effects():
    components = [{'id': 'one', 'purl': 'pkg:pypi/project@1', 'repo': None}, {'id': 'two', 'purl': 'pkg:pypi/project@1', 'repo': None}]
    key = package_ref(components[0]['purl'])['key']
    cache = {key: {'status': 'ambiguous', 'candidates': [{'repository': 'acme/project'}, {'repository': 'other/project'}]}}
    options = candidate_options(components, cache)
    observations = {c['id']: unknown_evidence() for c in components}
    original = score(observations['one'], [5, 3, 1], ['review'])
    overrides, provenance = {}, {}
    assert apply_candidates([], options, overrides, observations, provenance) == 0 and not overrides
    with pytest.raises(ValueError):
        apply_candidates(['one → acme/project', 'one → other/project'], options, overrides, observations, provenance)
    assert not overrides
    assert apply_candidates(['one → acme/project', 'two → acme/project'], options, overrides, observations, provenance) == 2
    assert overrides == {'one': 'acme/project', 'two': 'acme/project'}
    assert provenance['one']['lookup_key'] == key
    assert score(observations['one'], [5, 3, 1], ['review']) == original


def test_auto_map_all_processes_221_packages_deduplicates_and_preserves_existing(monkeypatch):
    calls, progress = [], []
    def lookup(purl):
        calls.append(purl)
        name = package_ref(purl)['parts'][0]
        return {'status': 'candidate', 'candidates': [{'repository': 'acme/' + name}]}
    monkeypatch.setattr('mapping.lookup_repository', lookup)
    components = [{'id': str(i), 'repo': None, 'purl': f'pkg:pypi/package{i}@1'} for i in range(221)]
    components += [{'id': 'duplicate', 'repo': None, 'purl': 'pkg:pypi/package0@1'},
                   {'id': 'existing', 'repo': 'verified/existing', 'purl': 'pkg:pypi/do-not-look-up@1'}]
    cache, overrides, provenance = {}, {}, {}
    evidence = {c['id']: unknown_evidence() for c in components}
    evidence['existing'] = {'factors': {'archived': 1}}
    summary = auto_map_all(components, cache, overrides, evidence, provenance, lambda i,n: progress.append((i,n)))
    assert len(calls) == 221 and len(set(calls)) == 221
    assert len(summary['applied']) == 222 and summary['remaining'] == {}
    assert progress[-1] == (221, 221) and [i for i,_ in progress] == list(range(1,222))
    assert overrides['duplicate'] == overrides['0'] == 'acme/package0'
    assert 'existing' not in overrides and evidence['existing']['factors']['archived'] == 1
    assert all(p['method'] == 'automatic' and 'not independently authenticated' in p['review'] for p in provenance.values())
    again = auto_map_all(components, cache, overrides, evidence, provenance)
    assert len(calls) == 221 and again['applied'] == {} and again['processed_packages'] == 0


def test_auto_map_all_cached_candidates_failed_retry_and_unresolved_sources(monkeypatch):
    components = [{'id': name, 'repo': None, 'purl': f'pkg:pypi/{name}@1'} for name in ['cached','ambiguous','failed','missing']]
    components += [{'id': 'unsupported', 'repo': None, 'purl': 'pkg:deb/debian/example@1'}]
    cache = {
        package_ref(c['purl'])['key']: {'status': c['id'], 'candidates': []} for c in components[:4]
    }
    cache[package_ref(components[0]['purl'])['key']] = {'status':'candidate', 'candidates':[{'repository':'acme/cached'}]}
    cache[package_ref(components[1]['purl'])['key']]['candidates'] = [{'repository':'one/project'}, {'repository':'two/project'}]
    cache[package_ref(components[3]['purl'])['key']]['status'] = 'not_found'
    calls = []
    monkeypatch.setattr('mapping.lookup_repository', lambda purl:calls.append(purl) or {'status':'failed','candidates':[]})
    evidence = {c['id']: unknown_evidence() for c in components}
    before = score(evidence['cached'], [4,2,5], ['review'])
    overrides, provenance = {}, {}
    result = auto_map_all(components, cache, overrides, evidence, provenance)
    assert calls == ['pkg:pypi/failed@1']
    assert result['applied'] == {'cached':'acme/cached'}
    assert result['remaining'] == {'ambiguous':'ambiguous','failed':'failed','missing':'not_found','unsupported':'unsupported'}
    assert score(evidence['cached'], [4,2,5], ['review']) == before
