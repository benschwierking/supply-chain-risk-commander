"""Offline inventory reader for SPDX 3 JSON-LD, not an RDF/schema validator.

Reads standard compact terms and expanded SPDX Core/Software IRIs. Inline
namespace maps are resolved locally; remote contexts and elements are never fetched.
"""
import re

TERMS = re.compile(r'^https://spdx\.org/rdf/3(?:\.\d+){0,2}/terms/(Core|Software)/([^/#]+)$')
SOFTWARE = {'Package', 'packageVersion', 'packageUrl', 'downloadLocation', 'homePage'}
CORE = {'SpdxDocument', 'CreationInfo', 'ExternalRef', 'ExternalIdentifier', 'name',
        'externalRef', 'externalIdentifier', 'locator', 'identifier', 'identifierLocator'}


def _list(value):
    return value if isinstance(value, list) else [value]


def parse_graph(data, repository):
    """Normalize package nodes into the application's existing component interface."""
    context = data.get('@context', []) if isinstance(data, dict) else []
    aliases = {}
    vocab = None
    for entry in _list(context):
        if isinstance(entry, dict):
            aliases.update({k: v.get('@id') if isinstance(v, dict) else v for k, v in entry.items() if not k.startswith('@')})
            vocab = entry.get('@vocab', vocab)

    def expand(value, seen=()):
        if not isinstance(value, str): return value
        if value in seen or len(seen) >= 12: return value
        if value in aliases and isinstance(aliases[value], str):
            return expand(aliases[value], seen+(value,))
        prefix, sep, suffix = value.partition(':')
        if sep and not suffix.startswith('//') and prefix in aliases:
            base = expand(aliases[prefix], seen+(value,))
            if isinstance(base, str): return base+suffix
        return value

    def term(value):
        value = expand(value)
        if not isinstance(value, str): return None
        if value in ('@type','type'): return 'type'
        if value in ('@id','spdxId'): return 'id'
        match = TERMS.fullmatch(value)
        if match:
            profile, local = match.groups()
            return ('software_'+local) if profile == 'Software' else local
        if value.startswith('software_') and value[9:] in SOFTWARE: return value
        if value in CORE: return value
        if vocab:
            match = TERMS.fullmatch(expand(vocab)+value)
            if match:
                profile, local=match.groups()
                return ('software_'+local) if profile=='Software' else local
        return None

    def normalize(node):
        normalized={}
        for key, value in node.items():
            canonical=term(key)
            if canonical:
                normalized.setdefault(canonical, []).extend(_list(value))
        return normalized

    def literals(values):
        found=[]
        for value in _list(values):
            if isinstance(value, str): found.append(value)
            elif isinstance(value, dict):
                literal=value.get('@value')
                if isinstance(literal,str): found.append(literal)
                elif isinstance(value.get('@id'),str): found.append(expand(value['@id']))
        return list(dict.fromkeys(found))

    graph=data.get('@graph') if isinstance(data,dict) else data
    if not isinstance(graph,list): raise ValueError('SPDX 3 @graph must be an array of nodes.')
    warnings=[]
    nodes={}
    queue=list(reversed(graph))
    while queue:
        node=queue.pop()
        if not isinstance(node,dict):
            warnings.append('Skipped a non-object SPDX 3 graph node.'); continue
        if '@graph' in node:
            if not isinstance(node['@graph'],list): raise ValueError('SPDX 3 @graph must be an array of nodes.')
            queue.extend(reversed(node['@graph']))
        fields=normalize(node)
        if not fields: continue
        identities=[expand(x) for x in literals(fields.get('id',[]))]
        if len(set(identities))>1: raise ValueError('SPDX 3 node has conflicting spdxId / @id identifiers.')
        identity=identities[0] if identities else None
        # Merge split descriptions of the same RDF resource; references have one identity.
        key=('id',identity) if identity else ('anonymous',len(nodes))
        combined=nodes.setdefault(key,{})
        for prop, values in fields.items():
            retained=combined.setdefault(prop,[])
            for value in values:
                if value not in retained: retained.append(value)
    index={key[1]:node for key,node in nodes.items() if key[0]=='id'}
    out=[]
    used={key[1] for key in nodes if key[0]=='id'}
    for key, node in nodes.items():
        types=[term(t) for t in literals(node.get('type',[]))]
        if 'software_Package' not in types: continue
        if len(out)>=1000: raise ValueError('Inventory limit is 1,000 components.')
        identity=key[1] if key[0]=='id' else None
        if not identity:
            identity=f'component-spdx3-{len(out)+1}'
            while identity in used: identity += '#generated'
            used.add(identity)
            warnings.append(f'SPDX 3 package lacks spdxId / @id; assigned {identity}.')

        def single(prop, default):
            values=literals(node.get(prop,[]))
            if len(values)>1:
                warnings.append(f'{identity}: conflicting {prop}; marked unknown.')
                return default
            return values[0] if values else default

        def linked(prop):
            for value in node.get(prop,[]):
                if isinstance(value,dict):
                    inline=normalize(value)
                    refs=literals(inline.get('id',[]))
                    if refs:
                        for ref in refs:
                            target=index.get(expand(ref))
                            if target is not None:
                                yield target
                            elif any(k not in ('id','type') for k in inline):
                                yield inline
                            else:
                                warnings.append(f'{identity}: unresolved {prop} reference {ref}; not fetched.')
                    elif inline:
                        yield inline
                    else:
                        warnings.append(f'{identity}: malformed {prop} reference; ignored.')
                    continue
                refs=literals(value)
                if not refs:
                    warnings.append(f'{identity}: malformed {prop} reference; ignored.')
                for ref in refs:
                    target=index.get(expand(ref))
                    if target is None:
                        warnings.append(f'{identity}: unresolved {prop} reference {ref}; not fetched.')
                    else: yield target

        candidates=[]
        for prop in ('software_packageUrl','software_downloadLocation','software_homePage'):
            candidates.extend(literals(node.get(prop,[])))
        for target in linked('externalRef'):
            candidates.extend(literals(target.get('locator',[])))
        for target in linked('externalIdentifier'):
            for prop in ('identifier','identifierLocator'):
                candidates.extend(literals(target.get(prop,[])))
        purls=list(dict.fromkeys(x for x in candidates if x.startswith('pkg:')))
        repos=[]
        for value in candidates:
            try:
                repo=repository(value)
            except ValueError:
                warnings.append(f'{identity}: malformed repository URL ignored.')
                continue
            if repo and repo not in repos: repos.append(repo)
        if len(repos)>1: warnings.append(f'{identity}: conflicting GitHub repository references; mapping left unknown.')
        if len(purls)>1: warnings.append(f'{identity}: multiple package URLs; purl left unknown.')
        repo=repos[0] if len(repos)==1 else None
        out.append({'id':identity,'name':single('name','Unnamed component'),
                    'version':single('software_packageVersion','unknown'),'repo':repo,
                    'purl':purls[0] if len(purls)==1 else None,
                    'mapping':'SBOM reference; not independently authenticated' if repo else 'Unmapped'})
    if not out: raise ValueError('No SPDX 3 software_Package components found in the graph.')
    return 'SPDX 3',out,warnings
