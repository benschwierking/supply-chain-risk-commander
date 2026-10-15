import json
import pytest
import requests
import evidence
from core import score


def test_inventory_collection_deduplicates_caches_and_retries(monkeypatch):
    components = [{'id':'one', 'repo':'owner/shared'}, {'id':'two', 'repo':'owner/shared'},
                  {'id':'three', 'repo':'owner/failed'}, {'id':'four', 'repo':None}]
    observations = {c['id']:evidence.unknown_evidence() for c in components}
    calls = []
    def collect(repo, *args):
        calls.append(repo)
        return {'mode':'live GitHub REST', 'factors':{'archived':0} if repo != 'owner/failed' or calls.count(repo)>1 else {}, 'sources':[]}
    monkeypatch.setattr(evidence, 'collect', collect)
    assert evidence.collect_inventory(components, observations, ['owner/shared', 'owner/shared', 'owner/failed']) == 2
    assert observations['one'] is observations['two']
    assert observations['four']['mode'] == 'unknown'
    assert score(observations['one'], [3,3,3])['exposure'] == 0
    assert score(observations['three'], [3,3,3])['exposure'] is None
    assert evidence.collect_inventory(components, observations, ['owner/shared', 'owner/failed']) == 0
    assert evidence.collect_inventory(components, observations, ['owner/shared', 'owner/failed'], retry=True) == 1
    assert calls == ['owner/shared', 'owner/failed', 'owner/failed']


def test_inventory_collection_scope_limit_and_mapping_validation(monkeypatch):
    monkeypatch.setattr(evidence, 'collect', lambda *a, **k:pytest.fail('Unexpected request'))
    with pytest.raises(ValueError, match='mappings'):
        evidence.collect_inventory([], {}, ['owner/not-mapped'])


def test_failed_requests_and_missing_metadata_never_become_zero_exposure(monkeypatch):
    def fail(*args, **kwargs): raise requests.Timeout('secret-token')
    monkeypatch.setattr(evidence.requests, 'get', fail)
    result = evidence.collect('owner/repo', 'secret-token')
    assert evidence.collection_status(result, 'owner/repo') == 'Unavailable; review errors'
    assert len(result['sources']) == 2
    assert all(source['http_status'] is None for source in result['sources'])
    assert score(result, [3,3,3])['completeness'] == 0
    assert 'secret-token' not in json.dumps(result)
    class Empty:
        status_code = 200
        def json(self): return {}
    monkeypatch.setattr(evidence.requests, 'get', lambda *args, **kwargs:Empty())
    assert evidence.collect('owner/repo')['factors'] == {}


def test_partial_request_is_marked_retryable(monkeypatch):
    calls = []
    class Metadata:
        status_code = 200
        def json(self): return {'archived':False, 'default_branch':'main'}
    def request(url, **kwargs):
        calls.append(url)
        if url.endswith('/repo'): return Metadata()
        raise requests.Timeout()
    monkeypatch.setattr(evidence.requests, 'get', request)
    components = [{'id':'one', 'repo':'owner/repo'}]
    observations = {}
    evidence.collect_inventory(components, observations, ['owner/repo'])
    assert evidence.collection_status(observations['one'], 'owner/repo') == 'Partial evidence; review errors'
    assert score(observations['one'], [3,3,3])['completeness'] == 15
    evidence.collect_inventory(components, observations, ['owner/repo'], retry=True)
    assert len(calls) == 8
