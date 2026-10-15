"""Selection and summaries shared by the interface and report. No network calls."""
import hashlib
import re
from core import CONTROLS, BASELINE


def selectable(measure):
    return bool(measure.get('title', '').strip() and any(action.strip() for action in measure.get('actions', [])))


def prepare_draft(draft):
    if 'generation_id' not in draft:
        draft['generation_id'] = hashlib.sha256((draft['generated_at'] + draft['context_fingerprint']).encode()).hexdigest()[:20]
    if 'action_cards' not in draft:
        cards = []
        if draft.get('text'):
            current = None
            for line in draft['text'].splitlines():
                match = re.match(r'^\s*(?:[-*•]|\d+[.)])\s+(.+)', line)
                if match:
                    current = {'title': match[1][:160], 'actions': [match[1]], 'editable': True}
                    cards.append(current)
                elif current is not None and line.strip():
                    current['actions'][-1] += '\n' + line.strip()
        draft['action_cards'] = cards
    for index, measure in enumerate(draft.get('controls', []) + draft['action_cards']):
        measure.setdefault('selection_id', hashlib.sha256((draft['generation_id'] + ':' + str(index) + ':' + measure['title']).encode()).hexdigest()[:20])
        measure.setdefault('selected', False)
    return draft.get('controls', []) + draft['action_cards']


def invalidate_draft(draft, stale):
    cards = prepare_draft(draft)
    draft['stale'] = bool(stale or draft.get('stale'))
    if draft['stale']:
        for card in cards: card['selected'] = False
        draft['reviewed'] = False
    return cards


def selected_plan(payload):
    groups = {}
    def add(title, actions, component, source, modeled):
        # Preserve distinct actions; combine only exact normalized content.
        key = (title.strip(), tuple(action.strip() for action in actions), modeled)
        item = groups.setdefault(key, {'control': title, 'actions': actions, 'components': [],
                                      'component_ids': [], 'source': source, 'modeled': modeled})
        if component['id'] not in item['component_ids']:
            item['component_ids'].append(component['id'])
            item['components'].append(component['name'] + ' / ' + component['version'] + ' [' + component['id'] + ']')
    for component in payload['components']:
        for key in component['assessment']['selected_controls']:
            if key in CONTROLS:
                add(CONTROLS[key][0], [], component, BASELINE, True)
        draft = payload.get('generated_control_measures', {}).get(component['id'], {})
        if not draft or draft.get('stale'): continue
        for measure in draft.get('controls', []) + draft.get('action_cards', []):
            if measure.get('selected') and selectable(measure):
                sources = measure.get('source_urls', [])
                add(measure['title'], measure.get('actions', []), component, sources[0] if sources else None, False)
    return list(groups.values())


def priorities(payload):
    scored = [c for c in payload['components'] if c['assessment']['exposure'] is not None]
    return sorted(scored, key=lambda c: (-c['assessment']['impact'] * c['assessment']['exposure'],
                                       -c['assessment']['exposure'], -c['assessment']['impact'], c['id']))[:10]


def priority_value(assessment):
    return round(assessment['impact'] * assessment['exposure'] / 100, 1) if assessment['exposure'] is not None else None


def justification(component):
    result = component['assessment']
    c, reach, recovery = result['impact_inputs']
    parts = [f'Mission {result["impact"]:g} (criticality {c}, reach {reach}, recovery {recovery}).']
    names = {'concentration': 'Top-account commit share', 'archived': 'Archived repository',
             'branch': 'Direct-commit safeguard gap', 'review': 'Review-setting gap'}
    drivers = sorted((d for d in result['drivers'] if d['observed'] > 0),
                     key=lambda d: -d['observed'] * d['weight'])[:2]
    for driver in drivers:
        parts.append(f'{names[driver["factor"]]} {driver["observed"]:.0%}.')
    if not drivers: parts.append('No positive exposure driver observed.')
    parts.append(f'Coverage {result["completeness"]}%.')
    return ' '.join(parts)
