"""Namespaced administrator-authored outbound graphs.

Protocol fields are validated by the installed sing-box, rather than a stale
allowlist. Explicit namespaced references can link administrator sections.
"""
import copy
import json
import re


def outbound_graph(value, allow_external=False):
    if isinstance(value, dict):
        value = value.get('outbounds') if set(value) == {'outbounds'} else [value]
    if not isinstance(value, list):
        raise ValueError('JSON outbound: объект или список объектов')
    try:
        encoded = json.dumps(value, allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        raise ValueError('Некорректный JSON outbound') from None
    graph = copy.deepcopy(value)
    tags = set()
    for index, item in enumerate(graph):
        if not isinstance(item, dict) or not isinstance(item.get('type'), str):
            raise ValueError('Каждый outbound требует поле type')
        if not re.fullmatch('[a-z][a-z0-9_-]{0,31}', item['type']):
            raise ValueError('Некорректный type outbound')
        item.setdefault('tag', 'entry' if index == 0 else 'node%d' % index)
        tag = item['tag']
        if not isinstance(tag, str) or not re.fullmatch('[A-Za-z0-9_.-]{1,64}', tag) or tag in tags:
            raise ValueError('Теги outbound должны быть уникальными: буквы, цифры, ._-')
        tags.add(tag)
    validate_references(graph, allow_external)
    return graph


def external_reference(tag):
    return tag in ('direct','proxy','auto','policy-block') or bool(re.fullmatch(r'(?:section_[a-f0-9]{16}_[A-Za-z0-9_.-]{1,64}|(?:pool|auto)_[a-f0-9]{16}|if_[a-f0-9]{12}|[a-f0-9]{32})',tag))


def validate_references(graph, allow_external=False):
    tags={item['tag'] for item in graph}
    if len(tags)!=len(graph):
        raise ValueError('Повторяющийся тег outbound')
    edges = {}
    for item in graph:
        refs = []
        for field in ('detour', 'default'):
            if field in item:
                if not isinstance(item[field], str):
                    raise ValueError('Ссылка outbound должна быть строкой')
                refs.append(item[field])
        for field in ('outbounds','fallbacks'):
            if field in item:
                if not isinstance(item[field],list) or any(not isinstance(x,str) for x in item[field]):raise ValueError(field+' должен быть списком тегов')
                refs.extend(item[field])
        if any(tag not in tags and not (allow_external and external_reference(tag)) for tag in refs):
            raise ValueError('Ссылка на отсутствующий outbound в этой секции')
        edges[item['tag']] = [tag for tag in refs if tag in tags]
    visited, visiting = set(), set()
    for tag in edges:
        stack=[(tag,False)]
        while stack:
            node,leaving=stack.pop()
            if leaving:
                visiting.remove(node);visited.add(node)
                continue
            if node in visited:continue
            if node in visiting:raise ValueError('Цикл ссылок между outbound')
            visiting.add(node);stack.append((node,True))
            stack.extend((child,False) for child in reversed(edges[node]))


def namespace_graph(graph, prefix, allow_external=False):
    graph = outbound_graph(graph, allow_external)
    names = {item['tag']: prefix + '_' + item['tag'] for item in graph}
    for item in graph:
        item['tag'] = names[item['tag']]
        for field in ('detour', 'default'):
            if field in item:
                item[field] = names.get(item[field],item[field])
        for field in ('outbounds','fallbacks'):
            if field in item:item[field]=[names.get(tag,tag) for tag in item[field]]
    return graph, graph[0]['tag'] if graph else None
