"""Explicit, bounded package-metadata lookups. Candidates always require review."""
import hashlib
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlparse
from xml.etree import ElementTree

import requests
from core import repository_input

MAX_LOOKUPS = 25
MAX_BYTES = 1024 * 1024
TIMEOUT = (3, 8)


def package_ref(purl):
    """Read only package coordinates; never use qualifier URLs or remote contexts."""
    if not isinstance(purl, str) or not purl.startswith('pkg:') or len(purl) > 4096:
        return None
    value = purl[4:].split('#', 1)[0].split('?', 1)[0]
    kind, sep, rest = value.partition('/')
    if not sep or not re.fullmatch('[a-z][a-z0-9.+-]*', kind):
        return None
    path, at, version = rest.rpartition('@')
    if not at or '/' in version:  # An npm scope is not a version separator.
        path, version = rest, ''
    parts = [unquote(part) for part in path.split('/')]
    version = unquote(version)
    if not parts or any(not part or part in ('.', '..') or re.search(r'[/\\\x00-\x20]', part) for part in parts):
        return None
    if version and (version in ('.', '..') or re.search(r'[/\\\x00-\x20]', version)):
        return None
    if kind == 'pypi' and len(parts) == 1:
        parts = [re.sub(r'[-_.]+', '-', parts[0]).lower()]
    ref = {'type': kind, 'parts': parts, 'version': version}
    ref['key'] = hashlib.sha256(json.dumps(ref, sort_keys=True).encode()).hexdigest()[:24]
    return ref


def purl_type(purl):
    ref = package_ref(purl)
    return ref['type'] if ref else 'missing / invalid PURL'


def lookup_plan(purl):
    ref = package_ref(purl)
    if not ref:
        return None
    kind, parts, version = ref['type'], ref['parts'], ref['version']
    plan = {**ref, 'url': None, 'direct': None}
    if kind == 'github' and len(parts) == 2:
        plan['direct'] = _github('/'.join(parts), shorthand=True)
    elif kind == 'golang' and len(parts) >= 3 and parts[0] == 'github.com':
        plan['direct'] = _github('/'.join(parts[1:3]), shorthand=True)
    elif kind == 'pypi' and len(parts) == 1 and re.fullmatch(r'[A-Za-z0-9_.-]+', parts[0]):
        name = re.sub(r'[-_.]+', '-', parts[0]).lower()
        plan['url'] = 'https://pypi.org/pypi/' + quote(name, safe='') + ('/' + quote(version, safe='') if version else '') + '/json'
    elif kind == 'npm' and (len(parts) == 1 or len(parts) == 2 and parts[0].startswith('@')):
        plan['url'] = 'https://registry.npmjs.org/' + quote('/'.join(parts), safe='@') + '/' + quote(version or 'latest', safe='')
    elif kind == 'maven' and len(parts) == 2 and version and re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*', parts[0]) and re.fullmatch(r'[A-Za-z0-9_.-]+', parts[1]):
        group = parts[0].replace('.', '/')
        artifact = quote(parts[1], safe='')
        release = quote(version, safe='')
        plan['url'] = f'https://repo.maven.apache.org/maven2/{group}/{artifact}/{release}/{artifact}-{release}.pom'
    return plan if plan['url'] or plan['direct'] else None


def _github(value, shorthand=False):
    if not isinstance(value, str) or '${' in value:
        return None
    value = value.strip().removeprefix('scm:git:').removeprefix('git+').replace('git@github.com:', 'https://github.com/').replace('ssh://git@github.com/', 'https://github.com/')
    if value.startswith('github:'):
        value = 'https://github.com/' + value[7:]
    if shorthand and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value):
        value = 'https://github.com/' + value
    try:
        parsed = urlparse(value)
        if parsed.hostname != 'github.com' or parsed.username or parsed.password or parsed.port:
            return None
        return repository_input(value)
    except ValueError:
        return None


def _candidates(plan, raw):
    values = []
    if plan['type'] == 'maven':
        # No DTDs/entities, parent fetching, property evaluation, or build execution.
        if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper() or b'\x00' in raw:
            raise ValueError('Unsupported XML declarations')
        root = ElementTree.fromstring(raw)
        for node in root.iter():
            node.tag = node.tag.rsplit('}', 1)[-1]
        for field in ('scm/url', 'scm/connection', 'scm/developerConnection', 'url'):
            value = root.findtext(field)
            if value: values.append((field, value))
    else:
        data = json.loads(raw)
        if not isinstance(data, dict): raise ValueError('Invalid metadata')
        if plan['type'] == 'pypi':
            info = data.get('info')
            if not isinstance(info, dict): raise ValueError('Invalid project metadata')
            urls = info.get('project_urls')
            if isinstance(urls, dict):
                values += [('project_urls.' + str(label), value) for label, value in urls.items()
                           if any(term in str(label).lower() for term in ('source', 'repo', 'code', 'homepage'))]
            values.append(('home_page', info.get('home_page')))
        else:
            repo = data.get('repository')
            values.append(('repository', repo.get('url') if isinstance(repo, dict) else repo))
            # A homepage can belong to another project. Use it only if no repo was supplied.
            if not repo: values.append(('homepage', data.get('homepage')))
    candidates = {}
    for field, value in values:
        repo = _github(value, shorthand=plan['type'] == 'npm' and field == 'repository')
        if repo:
            candidates.setdefault(repo.lower(), {'repository': repo, 'url': 'https://github.com/' + repo, 'fields': []})['fields'].append(field)
    return list(candidates.values())


def lookup_repository(purl):
    plan = lookup_plan(purl)
    result = {'schema': 'hephaestus-repository-lookup/1.0', 'status': 'unsupported', 'candidates': [],
              'retrieved_at': datetime.now(timezone.utc).isoformat(), 'source_url': None,
              'message': 'No supported lookup for this package URL. Add a verified repository manually.'}
    if not plan: return result
    result.update(package={'type': plan['type'], 'path': '/'.join(plan['parts']), 'version': plan['version']}, source_url=plan['url'])
    if plan['direct']:
        repo = plan['direct']
        result.update(status='candidate', candidates=[{'repository': repo, 'url': 'https://github.com/' + repo, 'fields': ['package URL']}], message='Repository named in the package URL; review before applying.')
        return result
    try:
        # No GitHub/Tavily credentials, .netrc authentication, cookies, or redirects.
        with requests.Session() as session:
            session.trust_env = False
            with session.get(plan['url'], headers={'Accept': 'application/json, application/xml', 'User-Agent': 'HEPHAESTUS/1.0 repository-mapping'}, timeout=TIMEOUT, allow_redirects=False, stream=True) as response:
                result['http_status'] = response.status_code
                if response.status_code != 200:
                    result.update(status='not_found' if response.status_code == 404 else 'failed', message='Package metadata not found at this registry.' if response.status_code == 404 else f'Registry request unavailable (HTTP {response.status_code}). Retry later or enter a mapping manually.')
                    return result
                chunks, size, started = [], 0, time.monotonic()
                for chunk in response.iter_content(16384):
                    size += len(chunk)
                    if size > MAX_BYTES or time.monotonic() - started > 15:
                        raise ValueError('Metadata limit')
                    chunks.append(chunk)
                candidates = _candidates(plan, b''.join(chunks))
        result.update(candidates=candidates, status='candidate' if len(candidates) == 1 else 'ambiguous' if candidates else 'not_found',
                      message='Publisher metadata; verify upstream identity before applying.' if candidates else 'No explicit GitHub source found. Parent POMs, private registries, and other hosts are not resolved; enter a mapping manually.')
    except (requests.RequestException, ValueError, ElementTree.ParseError, RecursionError):
        result.update(status='failed', message='Registry lookup failed or returned unsupported metadata. Retry later or enter a mapping manually.')
    return result


def pending_lookups(components, cache, retry=False):
    pending = {}
    for component in components:
        plan = lookup_plan(component.get('purl'))
        if component.get('repo') or not plan: continue
        previous = cache.get(plan['key'])
        if (previous is None and not retry) or (retry and previous and previous.get('status') == 'failed'):
            pending.setdefault(plan['key'], component['purl'])
    return pending


def lookup_batch(purls, cache, retry=False, progress=None):
    work = {}
    for purl in purls:
        plan = lookup_plan(purl)
        if not plan: continue
        previous = cache.get(plan['key'])
        if previous is None or retry and previous.get('status') == 'failed':
            work.setdefault(plan['key'], purl)
    work = dict(list(work.items())[:MAX_LOOKUPS])
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(lookup_repository, purl): key for key, purl in work.items()}
        for done, future in enumerate(as_completed(futures), 1):
            key = futures[future]
            cache[key] = future.result()
            if progress: progress(done, len(work))
    return cache


def candidate_options(components, cache):
    options = {}
    for component in components:
        ref = package_ref(component.get('purl'))
        if component.get('repo') or not ref: continue
        record = cache.get(ref['key'], {})
        for candidate in record.get('candidates', []):
            value = component['id'] + ' → ' + candidate['repository']
            options[value] = (component['id'], candidate['repository'], ref['key'])
    return options


def apply_candidates(selected, options, overrides, evidence, provenance):
    chosen = [options[value] for value in selected if value in options]
    ids = [item[0] for item in chosen]
    if len(ids) != len(set(ids)):
        raise ValueError('Choose only one repository per component. Conflicting suggestions were not applied.')
    from evidence import unknown_evidence
    for ref, repo, key in chosen:
        overrides[ref] = repo
        evidence[ref] = unknown_evidence()
        provenance[ref] = {'lookup_key': key, 'repository': repo, 'review': 'User selected and applied; upstream identity not independently authenticated'}
    return len(chosen)
