# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Immutable passive value DAGs for self-contained execution provenance.

Views have the same mapping/tuple reads as inline evidence. Their closed codecs
write one checked node table, not expanded copies of earlier history. Ordered
sequences share prefixes, including successive acknowledged history snapshots.
"""
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
import hashlib
import json
import math
from types import MappingProxyType

from bytefault.core.contracts import ContractError

FORMAT = 'bytefault.provenance'
VERSION = 1


def _fail(code, message):
    raise ContractError('provenance', code, message)


def _identity(node):
    return hashlib.sha256(json.dumps(node, ensure_ascii=True, allow_nan=False,
        separators=(',', ':')).encode('utf-8')).hexdigest()


class ProvenanceMapping(Mapping):
    __slots__ = ('_store', '_node')

    def __init__(self, store, node):
        object.__setattr__(self, '_store', store)
        object.__setattr__(self, '_node', node)

    def __setattr__(self, name, value):
        raise TypeError('provenance views are immutable')

    def __iter__(self):
        return (key for key, _ in self._store.nodes[self._node][1])

    def __len__(self):
        return len(self._store.nodes[self._node][1])

    def __getitem__(self, key):
        for name, child in self._store.nodes[self._node][1]:
            if name == key: return self._store.value(child)
        raise KeyError(key)

    def __getattr__(self, key):
        try: return self[key]
        except KeyError as exc: raise AttributeError(key) from exc

    def __eq__(self, other):
        if isinstance(other, ProvenanceMapping) and self._node == other._node: return True
        return Mapping.__eq__(self, other)

    def __repr__(self):
        return f'ProvenanceMapping({self._node}, keys={tuple(self) !r})'


class ProvenanceSequence(tuple):
    def __new__(cls, store, node, values):
        value = tuple.__new__(cls, values)
        object.__setattr__(value, '_store', store)
        object.__setattr__(value, '_node', node)
        return value

    def __setattr__(self, name, value):
        raise TypeError('provenance views are immutable')

    def __getattribute__(self, name):
        value = tuple.__getattribute__(self, name)
        return MappingProxyType(value) if name == '__dict__' else value

    def __eq__(self, other):
        if isinstance(other, ProvenanceSequence) and self._node == other._node: return True
        return tuple.__eq__(self, other)

    __hash__ = tuple.__hash__

    def __repr__(self):
        return f'ProvenanceSequence({self._node}, length={len(self)})'


VIEWS = (ProvenanceMapping, ProvenanceSequence)


def is_view(value):
    return isinstance(value, VIEWS)


def _children(node):
    tag, data = node
    if tag == 'mapping': return tuple(child for _, child in data)
    if tag == 'append': return data
    return ()


class _Store:
    def __init__(self, nodes):
        self.nodes = MappingProxyType(nodes)
        self.cache = {}

    def value(self, identity):
        if identity in self.cache: return self.cache[identity]
        tag, data = self.nodes[identity]
        if tag == 'mapping': value = ProvenanceMapping(self, identity)
        elif tag in ('empty', 'append'):
            children, current = [], identity
            while self.nodes[current][0] == 'append':
                current, child = self.nodes[current][1]
                children.append(child)
            value = ProvenanceSequence(self, identity, (self.value(child) for child in reversed(children)))
        elif tag == 'bytes': value = bytes.fromhex(data)
        else: value = data
        self.cache[identity] = value
        return value

    def closure(self, root):
        needed, pending = {}, [root]
        while pending:
            identity = pending.pop()
            if identity in needed: continue
            node = self.nodes[identity]
            needed[identity] = node
            pending.extend(_children(node))
        return needed


def export(value):
    """A JSON-compatible archive; the selected value owns all reachable nodes."""
    if not is_view(value):
        wrapper = pack({'value': value})
        root = wrapper._store.nodes[wrapper._node][1][0][1]
        store = wrapper._store
    else:
        root, store = value._node, value._store
    nodes = {}
    for identity, (tag, data) in store.closure(root).items():
        if tag == 'mapping': data = [[key, child] for key, child in data]
        elif tag == 'append': data = list(data)
        nodes[identity] = [tag, data]
    return {'format': FORMAT, 'version': VERSION, 'root': root, 'nodes': nodes}


def load(archive):
    """Validate references/content/acyclicity before returning a passive view."""
    if not isinstance(archive, Mapping) or archive.get('format') != FORMAT:
        _fail('malformed', 'bytefault.provenance archive required')
    if type(archive.get('version')) is not int or archive['version'] != VERSION:
        _fail('unsupported_version', repr(archive.get('version')))
    if set(archive) != {'format', 'version', 'root', 'nodes'} or not isinstance(archive['nodes'], Mapping):
        _fail('malformed', 'complete root/node table required')
    nodes = {}
    for identity, raw in archive['nodes'].items():
        if not isinstance(identity, str) or not isinstance(raw, (list, tuple)) or len(raw) != 2:
            _fail('malformed', 'identified tagged nodes required')
        tag, data = raw
        if tag == 'mapping':
            if not isinstance(data, (list, tuple)):
                _fail('malformed', 'ordered mapping entries required')
            pairs, keys = [], set()
            for pair in data:
                if not isinstance(pair, (list, tuple)) or len(pair) != 2 or not isinstance(pair[0], str):
                    _fail('malformed', 'string key/reference pairs required')
                if pair[0] in keys: _fail('malformed', 'duplicate mapping key')
                keys.add(pair[0]); pairs.append(tuple(pair))
            data = tuple(pairs)
        elif tag == 'append':
            if not isinstance(data, (list, tuple)) or len(data) != 2:
                _fail('malformed', 'sequence prefix/item references required')
            data = tuple(data)
        elif tag == 'empty':
            if data is not None: _fail('malformed', 'empty sequence payload must be null')
        elif tag == 'bytes':
            try:
                if not isinstance(data, str) or bytes.fromhex(data).hex() != data:
                    _fail('malformed', 'canonical exact hexadecimal bytes required')
            except ValueError as exc: _fail('malformed', str(exc))
        elif tag == 'scalar':
            if data is not None and type(data) not in (str, int, float, bool):
                _fail('malformed', 'passive scalar required')
            if type(data) is float and not math.isfinite(data): _fail('malformed', 'finite scalar required')
        else: _fail('unsupported_node', str(tag))
        nodes[identity] = (tag, data)
    root = archive['root']
    if not isinstance(root, str) or root not in nodes: _fail('missing_reference', 'root not retained')
    # Iterative traversal also handles long chronological sequence prefixes.
    colors, pending = {}, [(root, False)]
    while pending:
        identity, finished = pending.pop()
        if finished:
            colors[identity] = 2
            continue
        if colors.get(identity) == 2: continue
        if colors.get(identity) == 1: _fail('cyclic_reference', identity)
        if identity not in nodes: _fail('missing_reference', identity)
        colors[identity] = 1
        pending.append((identity, True))
        for child in reversed(_children(nodes[identity])):
            if not isinstance(child, str) or child not in nodes: _fail('missing_reference', str(child))
            pending.append((child, False))
        if nodes[identity][0] == 'append' and nodes[nodes[identity][1][0]][0] not in ('empty', 'append'):
            _fail('malformed', 'sequence prefix must be a sequence')
    if len(colors) != len(nodes): _fail('unreachable_node', 'node table contains unrelated values')
    for identity, node in nodes.items():
        if _identity(node) != identity: _fail('conflicting_reference', identity)
    return _Store(nodes).value(root)


def pack(value):
    """Intern exact passive values, importing existing views without expansion."""
    nodes, active, imports = {}, set(), set()
    def add(node):
        identity = _identity(node)
        previous = nodes.setdefault(identity, node)
        if previous != node: _fail('conflicting_reference', identity)
        return identity
    def encode(item):
        if is_view(item):
            key = (id(item._store), item._node)
            if key not in imports:
                pending = [item._node]
                while pending:
                    identity = pending.pop()
                    node = item._store.nodes[identity]
                    if identity in nodes:
                        if nodes[identity] != node: _fail('conflicting_reference', identity)
                        continue
                    nodes[identity] = node
                    pending.extend(_children(node))
                imports.add(key)
            return item._node
        if isinstance(item, bytes): return add(('bytes', item.hex()))
        if item is None or type(item) in (str, int, float, bool):
            if type(item) is float and not math.isfinite(item): _fail('malformed', 'finite scalar required')
            return add(('scalar', item))
        if not (is_dataclass(item) or isinstance(item, (Mapping, tuple, list))):
            _fail('malformed', 'passive mapping/sequence/value required: ' + type(item).__name__)
        identity = id(item)
        if identity in active: _fail('cyclic_reference', 'cyclic input container')
        active.add(identity)
        try:
            if is_dataclass(item): pairs = ((f.name, getattr(item, f.name)) for f in fields(item))
            elif isinstance(item, Mapping): pairs = item.items()
            else:
                root = add(('empty', None))
                for child in item: root = add(('append', (root, encode(child))))
                return root
            entries = []
            for key, child in pairs:
                if not isinstance(key, str): _fail('malformed', 'string mapping keys required')
                entries.append((key, encode(child)))
            return add(('mapping', tuple(entries)))
        finally: active.remove(identity)
    root = encode(value)
    return _Store(nodes).value(root)
