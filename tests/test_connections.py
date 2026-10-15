import json
import pytest
import requests
from connections import check_credential


@pytest.mark.parametrize(('service','data'), [('github',{'login':'example'}), ('tavily',{'key':{'usage':2,'limit':100}})])
def test_read_only_credential_check(service, data, monkeypatch):
    calls=[]
    class Response:
        status_code=200
        def json(self): return {**data,'extra_private_data':'discard-this'}
    def get(url, **kwargs):
        calls.append((url,kwargs))
        return Response()
    monkeypatch.setattr('connections.requests.get',get)
    result=check_credential(service,'secret-key','project-value')
    assert result['state']=='accepted'
    assert calls[0][0].endswith('/user' if service=='github' else '/usage')
    assert calls[0][1]['headers']['Authorization']=='Bearer secret-key'
    assert calls[0][1]['timeout']==(3,8) and calls[0][1]['allow_redirects'] is False
    assert all(value not in json.dumps(result) for value in ['secret-key','project-value','discard-this'])


@pytest.mark.parametrize(('status','state'),[(401,'rejected'),(403,'unverified'),(429,'unverified'),(500,'unverified'),(302,'unverified')])
def test_rejection_is_distinct_from_unavailability(status,state,monkeypatch):
    class Response: status_code=status
    monkeypatch.setattr('connections.requests.get',lambda *a,**k:Response())
    assert check_credential('github','secret')['state']==state


def test_missing_timeout_and_malformed_response(monkeypatch):
    monkeypatch.setattr('connections.requests.get',lambda *a,**k:pytest.fail('Unexpected request'))
    assert check_credential('github','')['state']=='missing'
    def fail(*args,**kwargs): raise requests.Timeout('secret-key')
    monkeypatch.setattr('connections.requests.get',fail)
    result=check_credential('tavily','secret-key')
    assert result['state']=='unverified' and 'secret-key' not in json.dumps(result)
    class Unexpected:
        status_code=200
        def json(self): return {'message':'secret-key'}
    monkeypatch.setattr('connections.requests.get',lambda *a,**k:Unexpected())
    assert check_credential('github','secret-key')['state']=='unverified'
