"""Offline dependency reach estimates. Containment never implies dependency."""
from collections import Counter


def attach_dependencies(data, components, warnings):
    if isinstance(data, dict) and isinstance(data.get('sbom'), dict):
        data = data['sbom']
    known = {c['id'] for c in components}
    allowed = set(known)
    present, edges, ambiguous = set(), set(), set()
    ignored = 0
    explicit_empty = False

    def edge(source, targets):
        nonlocal ignored, explicit_empty
        if not isinstance(source, str) or source not in allowed or source in ambiguous:
            ignored += 1
            return
        present.add(source)
        if targets == []: explicit_empty = True
        for target in targets if isinstance(targets, list) else [targets]:
            if not isinstance(target, str) or target not in allowed or target in ambiguous:
                ignored += 1
                continue
            present.add(target)
            if target != source:
                edges.add((source, target))

    if isinstance(data, dict) and data.get('bomFormat') == 'CycloneDX':
        raw_ids = []
        stack = list(data.get('components', []))
        while stack:
            item = stack.pop()
            if not isinstance(item, dict): continue
            if isinstance(item.get('bom-ref'), str): raw_ids.append(item['bom-ref'])
            if isinstance(item.get('components'), list): stack.extend(item['components'])
        ambiguous = {ref for ref, count in Counter(raw_ids).items() if count > 1}
        metadata = data.get('metadata', {})
        root = metadata.get('component', {}) if isinstance(metadata, dict) else {}
        if isinstance(root, dict) and isinstance(root.get('bom-ref'), str): allowed.add(root['bom-ref'])
        for item in data.get('dependencies', []) or []:
            if isinstance(item, dict) and 'dependsOn' in item:
                edge(item.get('ref'), item['dependsOn'])
    elif isinstance(data, dict) and str(data.get('spdxVersion', '')).startswith('SPDX-2.'):
        counts = Counter(p.get('SPDXID') for p in data.get('packages', []) if isinstance(p, dict) and isinstance(p.get('SPDXID'), str))
        ambiguous = {ref for ref, count in counts.items() if count > 1}
        reverse = {'DEPENDENCY_OF', 'BUILD_DEPENDENCY_OF', 'DEV_DEPENDENCY_OF',
                   'OPTIONAL_DEPENDENCY_OF', 'PROVIDED_DEPENDENCY_OF', 'TEST_DEPENDENCY_OF', 'RUNTIME_DEPENDENCY_OF'}
        for item in data.get('relationships', []) or []:
            if not isinstance(item, dict): continue
            kind, source, target = item.get('relationshipType'), item.get('spdxElementId'), item.get('relatedSpdxElement')
            if kind in reverse: source, target = target, source
            if kind == 'DEPENDS_ON' or kind in reverse:
                if target == 'NONE': edge(source, [])
                elif target != 'NOASSERTION': edge(source, [target])
    elif isinstance(data, list) or isinstance(data, dict) and '@graph' in data:
        from spdx3 import graph_nodes
        nodes, _, _, term, literals, normalize, expand = graph_nodes(data)
        def refs(values):
            output = []
            for value in values:
                if isinstance(value, dict) and '@value' not in value:
                    output.extend(expand(x) for x in literals(normalize(value).get('id', [])))
                else: output.extend(expand(x) for x in literals(value))
            return output
        for node in nodes.values():
            kinds = [term(x) for x in literals(node.get('relationshipType', []))]
            if len(kinds) != 1 or kinds[0] not in ('dependsOn', 'hasOptionalDependency', 'hasProvidedDependency'): continue
            sources = refs(node.get('from', []))
            if len(sources) == 1: edge(sources[0], refs(node.get('to', [])))
    parents = {ref: set() for ref in allowed}
    children = {ref: set() for ref in allowed}
    for source, target in edges:
        parents[target].add(source)
        children[source].add(target)
    for component in components:
        ref = component['id']
        # Missing graphs/references must not look like measured low reach.
        usable = bool(edges or explicit_empty) and ref in present and ref not in ambiguous
        visited, pending = {ref}, list(parents[ref])
        while pending:
            parent = pending.pop()
            if parent in visited: continue
            visited.add(parent)
            pending.extend(parents[parent] - visited)
        component['dependency'] = {
            'status': 'observed_graph' if usable else 'unavailable',
            'depends_on': sorted(children[ref]),
            'dependent_count': len((visited - {ref}) & known) if usable else None,
            'partial': bool(ignored),
        }
    if ignored: warnings.append(f'Dependency graph: ignored {ignored} unresolved or ambiguous reference(s); reach estimates use available links only.')


def reach_for_count(count):
    return 1 if count <= 1 else 2 if count <= 4 else 3 if count <= 9 else 4 if count <= 24 else 5
