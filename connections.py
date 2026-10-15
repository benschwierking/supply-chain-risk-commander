"""Read-only credential checks. Never persist tokens or raw service responses."""
import hashlib
import json
from datetime import datetime, timezone
import requests


def connection_key(*values):
    return hashlib.sha256(json.dumps(values).encode()).hexdigest()


def check_credential(service, secret, project_id=''):
    label = 'GitHub token' if service == 'github' else 'Tavily API key'
    result = {'state':'missing', 'message':f'{label} not supplied.',
              'checked_at':datetime.now(timezone.utc).isoformat()}
    if not secret: return result
    headers = {'Authorization':'Bearer '+secret, 'Accept':'application/json'}
    if service == 'github':
        url = 'https://api.github.com/user'
        headers.update({'Accept':'application/vnd.github+json', 'X-GitHub-Api-Version':'2022-11-28'})
    elif service == 'tavily':
        url = 'https://api.tavily.com/usage'
        if project_id: headers['X-Project-ID'] = project_id
    else:
        raise ValueError('Unknown credential service.')
    try:
        response = requests.get(url, headers=headers, timeout=(3,8), allow_redirects=False)
        status = response.status_code
        if status == 200:
            data = response.json()
            valid = isinstance(data, dict) and (isinstance(data.get('login'), str) if service == 'github' else isinstance(data.get('key'), dict))
            if not valid: raise ValueError('Unexpected authentication response')
            result.update(state='accepted', message=f'{label} accepted. '+(
                'Individual repository settings may still require additional read permissions.' if service == 'github' else
                'Usage endpoint accepted the key'+(' and project ID.' if project_id else '.')+' No searches were run.'))
        elif status == 401:
            result.update(state='rejected', message=f'{label} not accepted (HTTP {status}). Replace an invalid, expired, or revoked credential.')
        else:
            reason = 'rate limited; wait and recheck' if status == 429 else 'check permissions, project ID, or service availability'
            result.update(state='unverified', message=f'{label} not verified (HTTP {status}); {reason}.')
    except (requests.RequestException, ValueError):
        result.update(state='unverified', message=f'{label} could not be verified. Check connectivity and recheck; this does not establish that the credential is invalid.')
    return result
