import json
import pytest
import requests
import local_llm
from core import BASELINE, score


def context():
    observation={'mode':'unknown','factors':{},'notes':['Missing repository settings.'],'sources':[]}
    return local_llm.control_context({'id':'pkg','name':'Example','version':'1','repo':None},observation,score(observation,[3,3,3]),'Single production service')


def proposals():
    return {'controls':[{'title':'Verify repository settings','rationale':'Review enforcement is unknown.',
                        'actions':['Identify the upstream owner.','Ask an authorized owner for review-setting evidence.'],
                        'verification':'Record the evidence URL, retrieval time, and reviewer.',
                        'priority':'High','source_urls':[BASELINE,'https://invented.invalid/claim']} ]}


@pytest.mark.parametrize('endpoint',['https://example.org/v1','http://192.168.1.5:1234/v1','http://127.0.0.1.attacker.test','file:///tmp/model','http://user:password@localhost:1234','http://localhost:1234/v1?key=secret','http://localhost:1234/#fragment'])
def test_remote_or_credential_bearing_endpoints_are_rejected(endpoint,monkeypatch):
    monkeypatch.setattr(local_llm,'_request',lambda *a,**k:pytest.fail('Endpoint was contacted'))
    with pytest.raises(ValueError): local_llm.list_models('OpenAI-compatible',endpoint,'secret')


def test_local_url_normalization_and_model_independence():
    assert local_llm.local_base_url('http://localhost:11434/api','Ollama')=='http://localhost:11434'
    assert local_llm.local_base_url('http://[::1]:1234','OpenAI-compatible')=='http://[::1]:1234/v1'
    assert local_llm.preferred_model(['arbitrary-llm','gpt-oss:20b'])=='arbitrary-llm'
    assert local_llm.preferred_model(['arbitrary-llm','gpt-oss:20b'],'gpt-oss:20b')=='gpt-oss:20b'


@pytest.mark.parametrize('provider',local_llm.PROVIDERS)
def test_generation_protocol_redacts_credentials_and_preserves_score(provider,monkeypatch):
    calls=[]
    original=context()
    original['operational_context']='Do not forward github-secret or tavily-secret or local-secret.'
    before=dict(original['assessment'])
    def request(method,url,key='',body=None,timeout=8):
        calls.append((method,url,key,body,timeout))
        content=json.dumps(proposals())
        return {'message':{'content':content}} if provider=='Ollama' else {'choices':[{'text':content}]} if provider=='OpenAI-compatible text' else {'choices':[{'message':{'content':content}}]}
    monkeypatch.setattr(local_llm,'_request',request)
    draft=local_llm.generate_controls(provider,'http://127.0.0.1:1234','gpt-oss:20b',original,'local-secret',secrets=('github-secret','tavily-secret'))
    _,url,key,body,timeout=calls[0]
    assert url.endswith('/api/chat' if provider=='Ollama' else '/v1/completions' if provider=='OpenAI-compatible text' else '/v1/chat/completions')
    assert key=='local-secret' and timeout==120 and body['stream'] is False
    assert all(secret not in json.dumps(body) for secret in ['local-secret','github-secret','tavily-secret'])
    assert all(secret not in json.dumps(draft) for secret in ['local-secret','github-secret','tavily-secret'])
    assert draft['controls'][0]['source_urls']==[BASELINE]
    assert draft['reviewed'] is False and original['assessment']==before
    assert 'tools' not in body and draft['model']=='gpt-oss:20b'


@pytest.mark.parametrize('reply',[None,''])
def test_empty_model_output_is_actionable(reply,monkeypatch):
    monkeypatch.setattr(local_llm,'_request',lambda *a,**k:{'message':{'content':reply}})
    with pytest.raises(ValueError,match='model|Model'): local_llm.generate_controls('Ollama','http://localhost:11434','gpt-oss:20b',context())

@pytest.mark.parametrize('reply',['Review dependency updates and prepare a tested rollback plan.','{"controls":[]}','{"controls":[{"title":"missing actions"}]}'])
def test_unstructured_models_keep_plain_text_without_inventing_fields(reply,monkeypatch):
    calls=[]
    def request(*args):
        calls.append(args)
        return {'message':{'content':reply}}
    monkeypatch.setattr(local_llm,'_request',request)
    draft=local_llm.generate_controls('Ollama','http://localhost:11434','a-different-llm',context(),structured=False)
    assert 'format' not in calls[0][3]
    assert draft['format']=='text' and draft['text']==reply and draft['controls']==[]


def test_transport_disables_proxies_redirects_and_limits_output(monkeypatch):
    calls=[]
    class Response:
        status_code=200
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def iter_content(self,size): yield json.dumps({'models':[{'name':'gpt-oss:20b'}]}).encode()
    class Session:
        trust_env=True
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def request(self,method,url,**kwargs):
            assert self.trust_env is False
            calls.append(kwargs)
            return Response()
    monkeypatch.setattr(local_llm.requests,'Session',Session)
    assert local_llm.list_models('Ollama','http://localhost:11434')==['gpt-oss:20b']
    assert calls[0]['allow_redirects'] is False and calls[0]['timeout']==(3,8)
    monkeypatch.setattr(local_llm,'MAX_RESPONSE_BYTES',2)
    with pytest.raises(ValueError,match='too large'): local_llm.list_models('Ollama','http://localhost:11434')

def test_local_credential_rejection_is_direct_and_sanitized(monkeypatch):
    class Response:
        status_code=401
        def __enter__(self): return self
        def __exit__(self,*args): pass
    class Session:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def request(self,*args,**kwargs): return Response()
    monkeypatch.setattr(local_llm.requests,'Session',Session)
    with pytest.raises(ValueError,match='access not accepted') as error:
        local_llm.list_models('Ollama','http://localhost:11434','secret-local-key')
    assert 'secret-local-key' not in str(error.value)
