import json
import pytest
import research
from contributor_lens.models import ContributorProfile
from core import score

class Github:
    def __init__(self,**kwargs): pass
    def close(self): pass
    def get_contributors(self,ref,limit):
        return [ContributorProfile(login='alice',name='Alice Example',html_url='https://github.com/alice',contributions=10)][:limit]

class Response:
    status_code=200
    def json(self):
        return {'request_id':'r1','results':[{'url':'https://example.org/alice','title':'Alice Example github.com/alice owner/repo','content':'Open source contributor','score':.9}]}

def test_matching_partial_and_no_secret(monkeypatch):
    monkeypatch.setattr(research,'GitHubClient',Github)
    count=[]
    def post(*a,**kw):
        count.append(kw)
        if len(count)==2: raise RuntimeError('sensitive-key github-secret project-secret')
        return Response()
    monkeypatch.setattr(research.requests,'post',post)
    result=research.research_repository('owner/repo',3,'github-secret','sensitive-key','project-secret')
    assert len(count)==2 and result['status']=='partial'
    assert result['contributors'][0]['outcome']=='Search incomplete'
    assert len(result['contributors'][0]['sources'])==1
    exported=json.dumps(result)
    assert all(secret not in exported for secret in ['sensitive-key','github-secret','project-secret'])
    assert 'review_priority' not in exported and 'identity_confidence' not in exported and 'location' not in exported
    assert count[0]['timeout']==(5,20)
    assert count[0]['headers']['X-Project-ID']=='project-secret'

def test_batch_limits_dedup_and_retry(monkeypatch):
    calls=[]
    def run(repo,*args):
        calls.append(repo);return {'status':'complete','repository':repo}
    monkeypatch.setattr(research,'research_repository',run)
    cache={}
    research.run_batch(['a/b','a/b','c/d'],3,'','key','',cache)
    assert calls==['a/b','c/d']
    research.run_batch(['a/b','c/d'],3,'','key','',cache)
    assert len(calls)==2
    cache['c/d:3']['status']='partial'
    research.run_batch(['a/b','c/d'],3,'','key','',cache,retry=True)
    assert calls==['a/b','c/d','c/d']
    with pytest.raises(ValueError): research.run_batch([f'a/r{i}' for i in range(6)],3,'','key','',{})
    assert research.run_batch(['a/b'],3,'','','',{})=={}

def test_search_budget_and_missing_key(monkeypatch):
    monkeypatch.setattr(research.requests,'post',lambda *a,**k:Response())
    client=research.SearchClient('key')
    client.search(query='one');client.search(query='two')
    with pytest.raises(RuntimeError): client.search(query='three')
    assert research.research_repository('a/b',3,'','')['status']=='not_run'
    with pytest.raises(ValueError): research.research_repository('a/b',4,'','key')

def test_research_does_not_change_exposure():
    e={'factors':{'archived':0,'review':1}}
    before=score(e,[3,3,3])
    e['contributor_research']={'contributors':[{'outcome':'No retained matches'}]}
    assert score(e,[3,3,3])==before

def test_full_batch_never_exceeds_thirty_searches(monkeypatch):
    class ThreePeople(Github):
        def get_contributors(self,ref,limit):
            return [ContributorProfile(login=f'user{i}',html_url=f'https://github.com/user{i}') for i in range(limit)]
    monkeypatch.setattr(research,'GitHubClient',ThreePeople)
    calls=[]
    def post(*args,**kwargs):
        calls.append(kwargs)
        return Response()
    monkeypatch.setattr(research.requests,'post',post)
    cache={}
    research.run_batch([f'owner/repo{i}' for i in range(5)],3,'','key','',cache)
    assert len(calls)==30 and sum(r['searches_attempted'] for r in cache.values())==30
    research.run_batch([f'owner/repo{i}' for i in range(5)],3,'','key','',cache)
    assert len(calls)==30
