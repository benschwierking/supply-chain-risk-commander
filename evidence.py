import requests
from datetime import datetime, timezone
from urllib.parse import quote

MAX_ASSESSMENT_REPOSITORIES = 25

def unknown_evidence():
    return {'mode':'unknown', 'factors':{}, 'notes':['No repository observations collected. Use Collect assessment evidence after reviewing the repository mapping.'], 'sources':[]}

def collection_status(observation, repo):
    if not repo: return 'Needs repository mapping'
    if observation.get('mode') == 'unknown' or not observation: return 'Not collected'
    if not observation.get('factors'): return 'Unavailable; review errors'
    if any(source.get('http_status') != 200 for source in observation.get('sources', [])):
        return 'Partial evidence; review errors'
    return 'Evidence collected'

def collect_inventory(components, evidence, repositories, token='', scorecard=False, retry=False, progress=None):
    """Collect once per mapped repository, reusing session evidence until explicit retry."""
    unique = list(dict.fromkeys(repositories))
    if len(unique) > MAX_ASSESSMENT_REPOSITORIES:
        raise ValueError('Select at most 25 repositories per assessment collection.')
    mapped = {component.get('repo') for component in components if component.get('repo')}
    if any(repo not in mapped for repo in unique):
        raise ValueError('Review repository mappings before collecting evidence.')
    collected = 0
    for index, repo in enumerate(unique):
        related = [component for component in components if component.get('repo') == repo]
        previous = next((evidence.get(component['id']) for component in related
                         if evidence.get(component['id'], {}).get('mode') == 'live GitHub REST'), None)
        incomplete = previous and (not previous.get('factors') or
                                   any(source.get('http_status') != 200 for source in previous.get('sources', [])))
        if previous is None or retry and incomplete:
            observation = collect(repo, token, scorecard)
            collected += 1
        else:
            observation = previous
        for component in related:
            evidence[component['id']] = observation
        if progress: progress(index + 1, len(unique), repo)
    return collected

def collect(repo, token='', scorecard=False):
    result={'mode':'live GitHub REST', 'repository':repo, 'fetched_at':datetime.now(timezone.utc).isoformat(), 'factors':{}, 'sources':[], 'notes':[], 'contributors':[]}
    if not repo:
        result['notes'].append('No GitHub repository mapping.'); return result
    headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
    if token: headers['Authorization']='Bearer '+token
    root='https://api.github.com/repos/'+repo
    def get(path):
        url=root+path
        try:
            r=requests.get(url,headers=headers,timeout=10)
            result['sources'].append({'url':url,'http_status':r.status_code})
            if r.status_code!=200:
                reason = {401:'token invalid or expired; replace it and retry' if token else 'authentication required for this endpoint; add a GitHub token with the required read access and retry',
                          403:'access denied or API rate limit reached; check token permissions and rate limits',
                          404:'repository or settings unavailable; check the mapping and access',
                          429:'API rate limit reached; wait before retrying'}.get(r.status_code, 'request failed; retry later')
                result['notes'].append(f'{path or "Repository"}: HTTP {r.status_code}; {reason}. Unavailable factors remain unknown.'); return None
            return r.json()
        except (requests.RequestException, ValueError) as exc:
            result['sources'].append({'url':url,'http_status':None})
            result['notes'].append(f'{path}: request unavailable ({type(exc).__name__}).'); return None
    meta=get('')
    if isinstance(meta,dict):
        if isinstance(meta.get('archived'), bool): result['factors']['archived']=float(meta['archived'])
        branch=meta.get('default_branch')
        if branch:
            b=get('/branches/'+quote(branch,safe=''))
            if isinstance(b,dict) and isinstance(b.get('protected'),bool):
                result['branch_protected_indicator']=b['protected']
                result['notes'].append('Protected flag is contextual only: does not prove prevention of direct commits or review enforcement.')
            protection=get('/branches/'+quote(branch,safe='')+'/protection')
            if isinstance(protection,dict):
                # Presence does not establish bypass restrictions, so branch enforcement remains unknown.
                reviews=protection.get('required_pull_request_reviews')
                if reviews is None: result['factors']['review']=1.0
                elif isinstance(reviews,dict):
                    result['factors']['review']=0.0 if reviews.get('required_approving_review_count',0)>=1 else 1.0
                    result['notes'].append('Review setting observed; author exclusion and bypass behavior require further verification.')
    people=get('/contributors?per_page=100')
    if isinstance(people,list) and people:
        total=sum(p.get('contributions',0) for p in people)
        result['contributors']=[{'login':p.get('login','anonymous'),'url':p.get('html_url'),'contributions':p.get('contributions',0)} for p in people]
        if total: result['factors']['concentration']=max(p.get('contributions',0) for p in people)/total
        result['notes'].append('Concentration is top-account share of commits in first 100 cached contributor records; not maintainer privilege or intent. Bots included; history may be truncated.')
    if scorecard:
        url='https://api.securityscorecards.dev/projects/github.com/'+repo
        try:
            r=requests.get(url,timeout=10); result['sources'].append({'url':url,'http_status':r.status_code})
            if r.ok: result['scorecard']=r.json()
            else: result['notes'].append('Scorecard unavailable; not used in score.')
        except (requests.RequestException,ValueError): result['notes'].append('Scorecard request failed; not used in score.')
    return result

def synthetic(index):
    profiles=[(.88,0,1,1),(.32,0,.2,.1),(.68,1,.8,.6),(.19,0,0,0),(.7,0,None,None),(.45,0,.4,.3)]
    values=profiles[index%len(profiles)]
    return {'mode':'SYNTHETIC scenario — not actual repository findings','fetched_at':None,
            'factors':dict(zip(['concentration','archived','branch','review'],values)), 'contributors':[],
            'sources':[], 'notes':['Illustrative values only; repository links identify SBOM mappings, not evidence supporting these values.']}
