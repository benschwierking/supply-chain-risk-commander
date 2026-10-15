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

def parse_sbom(data):
    if isinstance(data, list) or isinstance(data, dict) and '@graph' in data:
        from spdx3 import parse_graph
        return parse_graph(data, repository)
    if not isinstance(data, dict): raise ValueError('SBOM must be a JSON object.')
    if data.get('bomFormat') == 'CycloneDX':
        fmt, raw = 'CycloneDX', data.get('components', [])
    elif str(data.get('spdxVersion', '')).startswith('SPDX-2.'):
        fmt, raw = 'SPDX', data.get('packages', [])
    else: raise ValueError('Use CycloneDX JSON, SPDX 2.x JSON, or an SPDX 3 JSON-LD @graph.')
    if not isinstance(raw, list): raise ValueError('Component inventory must be an array.')
    out, warnings, ids = [], [], set()
    def visit(items):
        for i in items:
            if not isinstance(i, dict):
                warnings.append('Skipped a non-object inventory entry.'); continue
            name = str(i.get('name') or 'Unnamed component')
            ref = str(i.get('bom-ref') or i.get('SPDXID') or f'component-{len(out)+1}')
            if ref in ids:
                warnings.append(f'Duplicate identifier {ref}; assigned distinct inventory identity.')
                ref = f'{ref}#{len(out)+1}'
            ids.add(ref)
            refs = i.get('externalReferences' if fmt == 'CycloneDX' else 'externalRefs', []) or []
            candidates = [x.get('url', x.get('referenceLocator', '')) for x in refs if isinstance(x, dict)] if isinstance(refs, list) else []
            candidates += [i.get('downloadLocation'), i.get('homepage'), i.get('purl')]
            repo = next((r for x in candidates if (r := repository(x))), None)
            purl = i.get('purl') or next((x for x in candidates if isinstance(x, str) and x.startswith('pkg:')), None)
            out.append(dict(id=ref, name=name, version=str(i.get('version', i.get('versionInfo', 'unknown'))), repo=repo, purl=purl, mapping='SBOM reference; not independently authenticated' if repo else 'Unmapped'))
            if isinstance(i.get('components'), list): visit(i['components'])
    visit(raw)
    if not out: raise ValueError('No components found in this SBOM.')
    if len(out) > 1000: raise ValueError('MVP limit is 1,000 components.')
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
