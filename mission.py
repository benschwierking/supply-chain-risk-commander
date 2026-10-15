"""Bulk mission-input assignment with per-scale overrides and reversible state."""
from copy import deepcopy
from dependencies import reach_for_count


def initialize(components, assessments):
    for component in components:
        ref = component['id']
        if ref not in assessments:
            assessments[ref] = {'inputs': [3, 3, 3], 'controls': [], 'input_sources': ['default'] * 3}
        else:
            # Existing sessions predate source tracking: preserve their analyst inputs.
            assessments[ref].setdefault('input_sources', ['manual'] * 3)


def assign(components, assessments, criticality=3, recovery=3, fallback=3, replace=False):
    if any(type(v) is not int or not 1 <= v <= 5 for v in (criticality, recovery, fallback)):
        raise ValueError('Mission scales must be integers from 1 to 5.')
    initialize(components, assessments)
    previous = {ref: deepcopy({k: value for k, value in saved.items() if k != 'controls'}) for ref, saved in assessments.items()}
    for component in components:
        saved = assessments[component['id']]
        dependency = component.get('dependency', {})
        count = dependency.get('dependent_count')
        usable = dependency.get('status') == 'observed_graph' and count is not None
        values = [criticality, reach_for_count(count) if usable else fallback, recovery]
        origins = ['shared', 'dependency_graph' if usable else 'fallback', 'shared']
        for index in range(3):
            if replace or saved['input_sources'][index] != 'manual':
                saved['inputs'][index] = values[index]
                saved['input_sources'][index] = origins[index]
        saved['mission_assignment'] = {'method': 'dependency-reach-v1', 'dependent_count': count,
            'graph_status': dependency.get('status', 'unavailable'), 'partial_graph': dependency.get('partial', False),
            'baseline': [criticality, fallback, recovery]}
    return previous


def undo(assessments, previous):
    for ref, saved in previous.items():
        controls = assessments[ref]['controls']
        assessments[ref] = deepcopy(saved)
        assessments[ref]['controls'] = controls
