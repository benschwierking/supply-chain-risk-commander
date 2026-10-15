import json
import pytest
import evidence


def observed(repo):
    return {'mode':'live GitHub REST','repository':repo,'factors':{'archived':0},'sources':[]}


@pytest.mark.parametrize('size',[221,1000])
def test_collect_all_deduplicates_and_caches(size,monkeypatch):
    components=[{'id':str(i),'repo':f'owner/repo{i}'} for i in range(size)]
    components += [{'id':'shared','repo':'owner/repo0'},{'id':'unmapped','repo':None}]
    calls=[]; observations={}
    monkeypatch.setattr(evidence,'collect',lambda repo,*a:calls.append(repo) or observed(repo))
    job=evidence.new_collection(components,observations,[c['repo'] for c in components if c['repo']])
    while job['state']=='running': evidence.step_collection(job,components,observations)
    assert len(calls)==size and len(set(calls))==size
    assert observations['shared'] is observations['0']
    assert evidence.collection_counts(job)=={'completed':size,'cached':0,'partial':0,'failed':0,'unmapped':1,'remaining':0}
    again=evidence.new_collection(components,observations,job['repositories'])
    assert again['state']=='complete' and len(again['cached'])==size


def test_pause_resume_rate_limit_partial_failure_and_changed_mappings(monkeypatch):
    components=[{'id':x,'repo':'o/'+x} for x in 'abcd']; observations={}; calls=[]
    def collect(repo,*a):
        calls.append(repo)
        if repo=='o/b' and calls.count(repo)==1:
            return {**observed(repo),'rate_limit':{'resume_at':1234}}
        if repo=='o/c': return {**observed(repo),'sources':[{'http_status':403}]}
        if repo=='o/d': raise ValueError('secret-value')
        return observed(repo)
    monkeypatch.setattr(evidence,'collect',collect)
    job=evidence.new_collection(components,observations,[c['repo'] for c in components])
    evidence.step_collection(job,components,observations)
    evidence.stop_collection(job)
    evidence.step_collection(job,components,observations)
    assert calls==['o/a']
    evidence.resume_collection(job,components,now=0)
    evidence.step_collection(job,components,observations)
    assert job['state']=='paused'
    evidence.resume_collection(job,components,now=1233)
    assert job['state']=='paused'
    evidence.resume_collection(job,components,now=1234)
    while job['state']=='running': evidence.step_collection(job,components,observations)
    assert calls==['o/a','o/b','o/b','o/c','o/d']
    assert 'secret-value' not in json.dumps(observations)
    retry=evidence.new_collection(components,observations,job['repositories'],retry=True)
    assert retry['pending']==['o/c','o/d']
    components[0]['repo']='new/mapping'
    evidence.step_collection(retry,components,observations)
    assert retry['state']=='cancelled' and len(calls)==5


def test_rate_limit_stops_remaining_endpoints(monkeypatch):
    class Limited:
        status_code=429
        headers={'retry-after':'120'}
        def json(self): return {'message':'API rate limit exceeded'}
    calls=[]
    monkeypatch.setattr(evidence.requests,'get',lambda url,**kw:calls.append(url) or Limited())
    monkeypatch.setattr(evidence.time,'time',lambda:100)
    result=evidence.collect('a/b','secret',True)
    assert len(calls)==1 and result['rate_limit']['resume_at']==220
    assert result['factors']=={} and 'secret' not in json.dumps(result)
