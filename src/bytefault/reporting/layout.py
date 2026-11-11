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

"""One readable incident directory per event in the selected result bin."""
from collections.abc import Mapping
from pathlib import Path
from datetime import datetime
import hashlib
import json
import re
import shutil
from uuid import uuid4

from bytefault.core.contracts import freeze
from bytefault.core.records import decode_value, encode_value


def _part(identity):
    return hashlib.sha256(str(identity).encode('utf-8')).hexdigest()[:16]


def _plain(value):
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    return value


def _name(value):
    """Keep protocol and core labels readable without allowing path components."""
    name = re.sub(r'[^A-Za-z0-9._-]', '_', str(value)).strip('._')
    return name[:80] or 'raw'


def _when(value):
    if value:
        try:
            return datetime.fromisoformat(value)
        except (TypeError, ValueError):
            pass
    return datetime.now().astimezone()


def _brief(value):
    text = (json.dumps(_plain(value), ensure_ascii=True, separators=(',', ':'), default=str)
            if isinstance(value, (Mapping, tuple, list)) else str(value))
    text = text.replace('\r', ' ').replace('\n', ' ').strip()
    return text if len(text) <= 300 else text[:297] + '...'


def _markdown_label(value):
    """Display an exact core name in a link without Markdown control syntax."""
    readable = ''.join(f'\\x{ord(char):02x}' if ord(char) < 32 or ord(char) == 127 else char
        for char in str(value))
    return re.sub(r'([\\`*_\[\]<>!&])', r'\\\1', readable)


class ReportLayout:
    def __init__(self, root):
        self.root = root
        self.base_dir = str(root.path)

    def _records(self, *, hydrate=True, run_id=None, event_id=None):
        """The journal discovers results; a distinct event file holds full detail."""
        for record in self.root.read(self.root.path).records:
            if record.kind != 'report_result':
                continue
            info = record.data['result']
            if run_id is not None and (info['run_id'], info['event_id']) != (run_id, event_id):
                continue
            if hydrate and info.get('projection') == 'event_json_v1':
                path = Path(info['event_path'])
                if 'event_length' not in info or 'event_sha256' not in info:
                    raise OSError('acknowledged event evidence binding unavailable: ' + str(path))
                try:
                    body = path.read_bytes()
                except OSError as error:
                    raise OSError('acknowledged event evidence unavailable: ' + str(path)) from error
                if len(body) != info['event_length'] or hashlib.sha256(body).hexdigest() != info['event_sha256']:
                    raise OSError('acknowledged event evidence content mismatch: ' + str(path))
                try:
                    full = decode_value(json.loads(body))
                except (ValueError, TypeError) as error:
                    raise OSError('acknowledged event evidence malformed: ' + str(path)) from error
                if any(full.get(key) != info.get(key) for key in ('run_id', 'event_id', 'report_id', 'event_path')):
                    raise OSError('acknowledged event evidence identity mismatch: ' + str(path))
                info = full
            yield info

    @staticmethod
    def _group(infos):
        events = {}
        for info in infos:
            key = (info['run_id'], info['event_id'])
            event = events.setdefault(key, {'run_id': key[0], 'event_id': key[1], 'occurrences': {}})
            occurrence = event['occurrences'].setdefault(info['occurrence_id'], {'revisions': []})
            occurrence['revisions'].append(info)
        return freeze(tuple(events.values()))

    def snapshot(self):
        """Refresh exact event detail without acquiring ownership or changing files."""
        return self._group(self._records())

    def report(self, request):
        from bytefault.reporting import ReportOutcome
        action = request.action
        context = request.context or {}
        result = self.record_result({'run_id': action.correlation.run_id, 'event_id': action.event_id,
            'occurrence_id': context.get('occurrence_id', action.observation_id),
            'report_id': request.report_id, 'correlation': action.correlation,
            'followup_action_id': action.action_id, 'observation_id': action.observation_id,
            'observed_at_utc': context.get('observation_time_utc'),
            'protocol_id': context.get('protocol_id', 'raw'),
            'collection_status': request.collection_status, 'collection_error': request.collection_error,
            'collection_items': request.collection_items, 'collection_operations': request.collection_operations,
            'collection_inventory_status': request.collection_inventory_status,
            'context': context}, request.artifacts)
        return ReportOutcome(request.report_id, action.event_id, action.action_id,
                             'succeeded', result['report_path'],
                             acquired_core_count=result['acquired_core_count'],
                             acquired_cores=result['acquired_cores'])

    def record_result(self, result_info, artifacts_dir=()):
        """Append a distinct report revision; never merge events by bytes or name."""
        with self.root._layout_lock:
            if self.root.closed:
                raise OSError('result owner released')
            info = dict(result_info)
            for key in ('run_id', 'event_id'):
                if not isinstance(info.get(key), str) or not info[key]:
                    raise ValueError(f'explicit {key} required')
            info.setdefault('occurrence_id', str(uuid4()))
            info.setdefault('report_id', str(uuid4()))
            events = self._group(self._records(hydrate=False))
            prior = next((event for event in events if (event['run_id'], event['event_id']) ==
                          (info['run_id'], info['event_id'])), None)
            if prior is None:
                base = _when(info.get('observed_at_utc')).strftime('%H%M%S') + '_' + _name(info.get('protocol_id', 'raw'))
                number = 0
                while True:
                    directory = self.root.path / (base if number == 0 else f'{base}_{number}')
                    if not directory.exists():
                        break
                    number += 1
                prior_revisions = ()
            else:
                prior_revisions = tuple(result for occurrence in prior['occurrences'].values()
                                        for result in occurrence['revisions'])
                directory = Path(prior_revisions[0]['report_path']).parent
            revision_number = len(prior_revisions)
            suffix = '' if revision_number == 0 else '-' + _part(info['report_id'])
            case_path = directory / ('case' + suffix + '.json')
            event_path = directory / ('event' + suffix + '.json')
            if isinstance(artifacts_dir, (str, Path)):
                source = Path(artifacts_dir)
                supplied = tuple(source.iterdir()) if source.is_dir() else (source,)
            else:
                supplied = tuple(Path(p) for p in artifacts_dir)
            items = {str(Path(item['path']).resolve()): item for item in info.get('collection_items', ())
                     if item.get('status') == 'cached' and item.get('path')}
            copies = []
            for number, source in enumerate(supplied, 1):
                is_core = str(source.resolve()) in items
                label = 'core' if is_core else 'artifact'
                copies.append(directory / f'{label}-{revision_number + 1:04d}-{number:04d}-{_name(source.name)}')
            context = info.get('context', {})
            inventory = context.get('source_inventory', {})
            inputs = tuple(Path(p).resolve() for p in inventory.get('paths', ()))
            directories = tuple(Path(p).resolve() for p in inventory.get('directories', ()))
            outputs = (directory / 'REPORT.md', case_path, event_path, *copies)
            for output in outputs:
                resolved = output.resolve()
                if (resolved in inputs or any(resolved.is_relative_to(parent) for parent in directories) or
                        (resolved.exists() and any(p.exists() and resolved.samefile(p) for p in inputs))):
                    raise ValueError('report destination aliases an input: ' + str(output))
            if event_path.exists() or case_path.exists() or any(path.exists() for path in copies):
                raise ValueError('report revision destination already exists')
            directory.mkdir(parents=True, exist_ok=prior is not None)
            associations, acquired_cores = [], []
            for source, destination in zip(supplied, copies):
                shutil.copy2(source, destination)
                item = items.get(str(source.resolve()))
                associations.append({'source': str(source), 'path': str(destination),
                    'association': item.get('association', 'unpaired_new_core') if item else 'supplied_artifact_not_causality'})
                if item is not None:
                    name = item.get('name')
                    exact_name = isinstance(name, str) and bool(name)
                    acquired_cores.append({'name': name if exact_name else None,
                        'name_status': 'exact' if exact_name else 'unavailable',
                        'path': str(destination), 'source': str(source),
                        'association': item.get('association', 'unpaired_new_core')})
            info.update(artifacts=tuple(associations), updated_at=datetime.now().astimezone().isoformat(),
                        acquired_core_count=len(acquired_cores), acquired_cores=tuple(acquired_cores),
                        report_path=str(directory / 'REPORT.md'), revision_path=str(directory),
                        event_path=str(event_path))
            portable = context.get('portable_case')
            if portable is not None:
                case_path.write_text(json.dumps(_plain(portable), ensure_ascii=True), encoding='utf-8')
                info['case_path'] = str(case_path)
            event_body = json.dumps(encode_value(info), ensure_ascii=True,
                separators=(',', ':')).encode('utf-8')
            event_path.write_bytes(event_body)
            # Required journal acknowledgment is the discoverability boundary.
            indexed = {key: value for key, value in info.items()
                       if key not in ('context', 'collection_items', 'collection_operations')}
            indexed['projection'] = 'event_json_v1'
            indexed['event_length'] = len(event_body)
            indexed['event_sha256'] = hashlib.sha256(event_body).hexdigest()
            self.root.append('report_result', {'run_id': info['run_id'], 'event_id': info['event_id'],
                'occurrence_id': info['occurrence_id'], 'report_id': info['report_id']}, {'result': indexed})
            self._render(info['run_id'], info['event_id'])
            return freeze(info)

    def _render(self, run_id, event_id):
        event = self._group(self._records(run_id=run_id, event_id=event_id))[0]
        revisions = [result for occurrence in event['occurrences'].values() for result in occurrence['revisions']]
        directory = Path(revisions[0]['report_path']).parent
        lines = ['# Event ' + directory.name, '', 'Event ID: ' + event_id, 'Run ID: ' + run_id, '',
                 'Observations and classifications are evidence; collection does not establish cause.', '']
        for result in revisions:
            context = result.get('context', {})
            decision = context.get('decision', {})
            observation = next((record.get('data', {}).get('observation') for record in context.get('records', ())
                if record.get('kind') == 'observation' and
                record.get('data', {}).get('observation', {}).get('observation_id') == result['observation_id']), None)
            correlation = result.get('correlation', {})
            lines.extend(['## Report ' + result['report_id'], '',
                'Observation: ' + _brief(result.get('observed_at_utc') or 'time unavailable'),
                'Trigger: ' + _brief(observation.get('kind', 'unknown') if observation else 'unknown') +
                    '; service=' + _brief(observation.get('service_readiness', 'unknown') if observation else 'unknown'),
                'Case/action/attempt: ' + ' / '.join(_brief(correlation.get(key, 'unknown'))
                    for key in ('case_id', 'action_id', 'attempt_id')),
                'Collection: ' + _brief(result.get('collection_status', 'unavailable')) +
                    ' (' + _brief(result.get('collection_inventory_status', 'unknown')) + ')',
                'Reporting action: ' + _brief(result.get('followup_action_id', 'unknown')), ''])
            acquired_cores = result.get('acquired_cores', ())
            if acquired_cores:
                count = len(acquired_cores)
                lines.extend([('**Multiple cores acquired: ' + str(count) + '**' if count > 1 else
                    'Acquired core: 1'), ''])
                for core in acquired_cores:
                    path = Path(core['path'])
                    label = (core['name'] if core.get('name_status') == 'exact' else
                        'Exact remote name unavailable')
                    lines.append('- [' + _markdown_label(label) + '](' +
                        path.relative_to(directory).as_posix() + ') — ' +
                        _brief(core['association']))
                lines.append('')
            if result.get('collection_error'):
                lines.extend(['Collection error: ' + _brief(result['collection_error']), ''])
            assessments = decision.get('assessments', ())
            if assessments:
                lines.extend(['### Assessments', ''])
                for assessment in assessments:
                    lines.append('- ' + _brief(assessment.get('rule', 'unknown')) + ': ' +
                                 _brief(assessment.get('classification', 'unknown')) +
                                 ' (' + _brief(assessment.get('uncertainty', 'unknown')) + ')')
                lines.append('')
            boundary = context.get('collection_boundary')
            if boundary:
                lines.extend(['Previous successful collection: ' + _brief(boundary.get('completed_at_utc', 'unknown')) +
                    ' (run ' + _brief(boundary.get('run_id', 'unknown')) +
                    ', action ' + _brief(boundary.get('followup_action_id', 'unknown')) + ')', ''])
            candidates = context.get('intervening_test_identities', ())
            if context.get('intervening_test_scope'):
                lines.extend(['Candidate window: ' + _brief(context['intervening_test_scope']), ''])
            if candidates:
                lines.extend(['### Known tests since that collection', '',
                    str(len(candidates)) + ' exact identities are in the linked event evidence.', ''])
                lines.extend('- ' + _brief(candidate.get('identity', {})) for candidate in candidates[:5])
                if len(candidates) > 6:
                    lines.append('- ...')
                if len(candidates) > 5:
                    lines.append('- ' + _brief(candidates[-1].get('identity', {})))
                lines.append('')
            # Retained inline results from the prior layout stored event
            # evidence inside their revision directory, without event_path.
            event_path = (Path(result['event_path']) if result.get('event_path') else
                          Path(result['revision_path']) / 'event.json')
            lines.extend(['[Exact event evidence](' + event_path.relative_to(directory).as_posix() + ')', ''])
            if result.get('case_path'):
                lines.extend(['[Runnable recorded case](' + Path(result['case_path']).relative_to(directory).as_posix() + ')', ''])
            core_paths = {core['path'] for core in acquired_cores}
            other_artifacts = tuple(artifact for artifact in result['artifacts']
                if artifact['path'] not in core_paths)
            if other_artifacts:
                lines.extend(['### Acquired files', ''])
                for artifact in other_artifacts:
                    path = Path(artifact['path'])
                    lines.append('- [' + path.name + '](' + path.relative_to(directory).as_posix() +
                                 ') — ' + _brief(artifact['association']))
                lines.append('')
        (directory / 'REPORT.md').write_text('\n'.join(lines), encoding='utf-8')
