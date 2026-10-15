"""Bounded adapter for the approved contributor-lens source discovery modules."""
from datetime import datetime, timezone
import requests
from contributor_lens.github_client import GitHubClient
from contributor_lens.models import RepoRef
from contributor_lens.tavily_client import TavilyEnricher

UPSTREAM_REVISION = '3b0b945370f6cf9be8aab0d6982c692d15d2e53b'
MAX_REPOSITORIES = 5
MAX_CONTRIBUTORS = 3

class SearchClient:
    def __init__(self, key, project_id=None):
        self.key, self.project_id = key, project_id
        self.calls = 0
    def search(self, **kwargs):
        if self.calls >= 2:
            raise RuntimeError('Contributor search allowance exhausted.')
        self.calls += 1
        headers = {'Authorization': 'Bearer '+self.key}
        if self.project_id:
            headers['X-Project-ID'] = self.project_id
        response = requests.post('https://api.tavily.com/search', json=kwargs, headers=headers, timeout=(5,20))
        if response.status_code != 200:
            raise RuntimeError(f'Tavily HTTP {response.status_code}; search incomplete.')
        return response.json()

def clean_text(value, secrets=()):
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, '[redacted]')
    return text

def research_repository(repo, top_n, github_token, tavily_key, project_id=None):
    if not tavily_key:
        return {'status':'not_run','error':'Tavily API key required.', 'contributors':[]}
    if not 1 <= top_n <= MAX_CONTRIBUTORS:
        raise ValueError('Choose 1–3 contributors per repository.')
    result = {'schema':'hephaestus-contributor-research/1.0','repository':repo,
              'upstream_revision':UPSTREAM_REVISION,'source_mode':'live',
              'retrieved_at':datetime.now(timezone.utc).isoformat(), 'status':'complete',
              'contributors':[], 'sources':[], 'searches_attempted':0,
              'limitations':['Source matching is heuristic and requires human confirmation.',
                            'No retained matches is not a negative finding about a contributor.',
                            'Research is excluded from exposure and scoring completeness.',
                            'Identity and U.S. Person status remain unverified.']}
    github = GitHubClient(token=github_token or None, timeout=10)
    try:
        ref = RepoRef.parse(repo)
        profiles = github.get_contributors(ref, limit=top_n)
        result['sources'].append('https://api.github.com/repos/'+repo+'/contributors')
        for profile in profiles:
            result['sources'].append(profile.html_url)
            client = SearchClient(tavily_key, project_id)
            enricher = TavilyEnricher(client=client, api_key=tavily_key)
            evidence, request_ids, queries = enricher.enrich(profile, ref, False)
            errors = getattr(enricher, 'errors', [])
            result['searches_attempted'] += client.calls
            if errors:
                result['status'] = 'partial'
            sources = []
            for item in evidence:
                # Retain only http(s) links; display text as text, never executable HTML.
                if not item.url.startswith(('https://','http://')): continue
                sources.append({'title':item.title,'url':item.url,'excerpt':item.excerpt,
                                'source_domain':item.source_domain,'query':item.query,
                                'heuristic_match':item.identity_match,'search_relevance':item.relevance})
            exact = any(s['heuristic_match']=='exact' for s in sources)
            outcome = 'Search incomplete' if errors else 'Heuristic exact match' if exact else 'Heuristic probable match' if sources else 'No retained matches'
            result['contributors'].append({'login':profile.login, 'github_url':profile.html_url,
                'contributions':profile.contributions,'outcome':outcome,'queries':queries,
                'request_ids':request_ids,'sources':sources,'errors':errors})
    except Exception:
        result['status'] = 'failed'
        result['error'] = 'GitHub contributor research failed; check credentials, connectivity, and rate limits.'
    finally:
        github.close()
    # Do not retain raw exception strings, secrets, profile demographics, or internal priority scores.
    import json
    return json.loads(clean_text(json.dumps(result), (tavily_key, github_token, project_id)))

def run_batch(repos, top_n, github_token, tavily_key, project_id, cache, retry=False, progress=None):
    unique = list(dict.fromkeys(repos))
    if len(unique)>MAX_REPOSITORIES:
        raise ValueError('Select at most five repositories per run.')
    if not tavily_key:
        return cache
    for index, repo in enumerate(unique):
        key=f'{repo}:{top_n}'
        previous=cache.get(key)
        should_run = (previous and previous.get('status') in ('partial','failed')) if retry else not previous
        if should_run:
            cache[key]=research_repository(repo, top_n, github_token, tavily_key, project_id)
        if progress: progress(index+1,len(unique),repo)
    return cache
