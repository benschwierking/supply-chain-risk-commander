"""Deterministic, auditable inventory and exposure model. No intent inference."""
import json
import re
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse

BASELINE = 'https://baseline.openssf.org/versions/2026-08-28'
CONTROLS = {
    'review': ('Independent human review', 'OSPS-QA-07.01', 'review', 0.65),
    'branch': ('Prevent direct primary-branch commits', 'OSPS-AC-03.01', 'branch', 0.75),
    'continuity': ('Document privileged members and responsibilities', 'OSPS-GV-01.01 / OSPS-GV-01.02', 'concentration', 0.20),
}
WEIGHTS = {'concentration': 30, 'archived': 15, 'branch': 30, 'review': 25}
MAX_SBOM_BYTES = 10 * 1024 * 1024

def read_sbom(raw):
    """Read uploaded bytes with actionable errors, without echoing file contents."""
    if len(raw) > MAX_SBOM_BYTES:
        raise ValueError('File exceeds the 10 MB upload limit.')
    if not raw.strip():
        raise ValueError('The file is empty. Upload a JSON SBOM exported by your inventory tool.')
    try:
        data = json.loads(raw)
    except UnicodeDecodeError:
        raise ValueError('Cannot decode the file. Export the SBOM as UTF-8 JSON.') from None
    except json.JSONDecodeError as exc:
        raise ValueError(f'Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}. Export the raw JSON file rather than a web page or formatted preview.') from None
    except RecursionError:
        raise ValueError('JSON nesting is too deep. Export a flatter component inventory.') from None
    try:
        return parse_sbom(data)
    except RecursionError:
        raise ValueError('Component nesting is too deep. Export a flatter component inventory.') from None

def repository(value):
    if not isinstance(value, str): return None
    value = unquote(value).removeprefix('git+').replace('git@github.com:', 'https://github.com/')
    if value.startswith('pkg:github/'):
        value = 'https://github.com/' + value[11:].split('@')[0].split('?')[0]
    p = urlparse(value)
    if p.hostname != 'github.com': return None
    parts = p.path.strip('/').split('/')
    if len(parts) < 2 or not all(re.fullmatch(r'[A-Za-z0-9_.-]+', x) for x in parts[:2]): return None
    return '/'.join(parts[:2]).removesuffix('.git')

def repository_input(value):
    value = value.strip()
    if not value: return None
    if re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value):
        value = 'https://github.com/' + value
    try:
        repo = repository(value)
    except ValueError:
        repo = None
    if not repo or any(part in ('.', '..', '') for part in repo.split('/')):
        raise ValueError('Enter a GitHub repository URL or owner/repository, or leave blank to remove the mapping.')
    return repo

def parse_sbom(data):
    warnings = []
    # The GitHub dependency-graph API wraps the SPDX document in an sbom field.
    if isinstance(data, dict) and not any(k in data for k in ('bomFormat', 'spdxVersion', '@graph')) and isinstance(data.get('sbom'), dict):
        data = data['sbom']
        warnings.append('Read the inventory from the JSON sbom wrapper.')
    if isinstance(data, list) or isinstance(data, dict) and '@graph' in data:
        from spdx3 import parse_graph
        fmt, out, graph_warnings = parse_graph(data, repository)
        return fmt, out, warnings + graph_warnings
    if not isinstance(data, dict): raise ValueError('The JSON does not contain an SBOM object or SPDX 3 graph. Upload an inventory document, not a quoted JSON string or assessment report.')
    if data.get('bomFormat') == 'CycloneDX':
        fmt, raw = 'CycloneDX', data.get('components', [])
    elif str(data.get('spdxVersion', '')).startswith('SPDX-2.'):
        fmt, raw = 'SPDX', data.get('packages', [])
    else: raise ValueError('Valid JSON, but its SBOM format was not recognized. Expected bomFormat: CycloneDX, spdxVersion: SPDX-2.x, or an SPDX 3 JSON-LD @graph. Export an SBOM in one of these formats; renaming a JSON file does not convert its contents.')
    if not isinstance(raw, list): raise ValueError('Component inventory must be an array.')
    out, ids = [], set()
    def visit(items):
        for i in items:
            if not isinstance(i, dict):
                warnings.append('Skipped a non-object inventory entry.'); continue
            name = str(i.get('name') or 'Unnamed component')
            ref = str(i.get('bom-ref') or i.get('SPDXID') or f'component-{len(out)+1}')
            if ref in ids:
                warnings.append(f'Duplicate identifier {ref}; assigned distinct inventory identity.')
                original, suffix = ref, len(out)+1
                while ref in ids:
                    ref = f'{original}#{suffix}'
                    suffix += 1
            ids.add(ref)
            refs = i.get('externalReferences' if fmt == 'CycloneDX' else 'externalRefs', []) or []
            candidates = [x.get('url', x.get('referenceLocator', '')) for x in refs if isinstance(x, dict)] if isinstance(refs, list) else []
            candidates += [i.get('downloadLocation'), i.get('homepage'), i.get('purl')]
            repo = None
            for value in candidates:
                try:
                    found = repository(value)
                except ValueError:
                    warnings.append(f'{ref}: malformed repository URL ignored.')
                    continue
                if found:
                    repo = found
                    break
            purl = i.get('purl') or next((x for x in candidates if isinstance(x, str) and x.startswith('pkg:')), None)
            out.append(dict(id=ref, name=name, version=str(i.get('version', i.get('versionInfo', 'unknown'))), repo=repo, purl=purl, mapping='SBOM reference; not independently authenticated' if repo else 'Unmapped'))
            if isinstance(i.get('components'), list): visit(i['components'])
    visit(raw)
    if not out: raise ValueError('No components found in this SBOM.')
    if len(out) > 1000: raise ValueError('Inventory limit is 1,000 components. Export a smaller component inventory.')
    return fmt, out, warnings

def score(evidence, impact, selected=()):
    """Unknown factors excluded from normalized exposure; completeness reported separately."""
    vals = evidence.get('factors', {})
    known = {k: vals[k] for k in WEIGHTS if isinstance(vals.get(k), (int, float)) and not isinstance(vals.get(k), bool)}
    denominator = sum(WEIGHTS[k] for k in known)
    drivers = []
    for k, v in known.items():
        reduction = max((c[3] for key, c in CONTROLS.items() if key in selected and c[2] == k), default=0)
        drivers.append(dict(factor=k, observed=round(max(0,min(1,v)),4), weight=WEIGHTS[k], modeled_reduction=reduction))
    before = sum(d['observed']*d['weight'] for d in drivers)/denominator*100 if denominator else None
    after = sum(d['observed']*d['weight']*(1-d['modeled_reduction']) for d in drivers)/denominator*100 if denominator else None
    return dict(impact=round(sum(impact)/15*100,1), exposure=round(before,1) if before is not None else None,
                residual=round(after,1) if after is not None else None, completeness=denominator, drivers=drivers,
                selected_controls=list(selected), impact_inputs=list(impact))

def sidecar(components, evidence, results, source, research=None):
    return dict(schema='hephaestus-risk-sidecar/1.1', application='HEPHAESTUS', contributor_research=research or {}, component_repository_map={c['id']:c.get('repo') for c in components}, generated_at=datetime.now(timezone.utc).isoformat(), source=source,
                model='weighted-observed-exposure-v1', baseline=BASELINE,
                limitations=['Ordinal decision support, not probability or maliciousness detection.', 'Unknown factors excluded; low completeness can hide exposure.', 'Repository-level present-day evidence is not release-specific.', 'Contributor identities and U.S. Person status unverified; authorized attestation required.', 'Mitigation effects are analyst assumptions, not verified implementation.'],
                components=[dict(**c, evidence=evidence.get(c['id'],{}), assessment=results[c['id']]) for c in components])

def report(payload):
    lines=['# HEPHAESTUS', f"Generated: {payload['generated_at']}", f"Evidence mode: {payload['source']}", '', '| Component | Impact | Exposure | Modeled residual | Completeness |', '|---|---:|---:|---:|---:|']
    for c in payload['components']:
        s=c['assessment']; name=c['name'].replace('|','\\|').replace('\n',' ')
        lines.append(f"| {name} {c['version']} | {s['impact']} | {s['exposure']} | {s['residual']} | {s['completeness']}% |")
    lines += ['', '## Interpretation'] + ['- '+x for x in payload['limitations']]
    lines += ['', 'Full evidence, drivers, source URLs, mission inputs, and selected controls are in the accompanying JSON sidecar.']
    lines += ['', '## Proposed enterprise disposition', '- Validate the package/repository mapping and release provenance.', '- Verify unknown safeguards before acceptance; a low index is not approval.', '- Require mission-owner review and an owner/expiry for exceptions.', '- Obtain authorized attestation for status questions; never infer from demographic or profile proxies.', '- Verify planned controls against OSPS Baseline v2026.08.28; simulation is not compliance evidence.']
    return '\n'.join(lines)
