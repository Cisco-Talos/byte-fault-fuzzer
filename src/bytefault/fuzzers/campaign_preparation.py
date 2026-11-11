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

"""Lazy non-executing campaign inspection over the ordinary family preparation."""
from uuid import uuid4
import sys
import threading
from bytefault.core.contracts import freeze, ContractError
from bytefault.fuzzers.campaign import selected_case


class CampaignPreparation:
    def __init__(self, application, request):
        self.application, self.request = application, request
        self.preparation_id = 'campaign-inspection-' + str(uuid4())
        self._done, self._families = False, None
        self._iterator = self._rows()
        self._execution = threading.Lock()
        self._cancelled = threading.Event()
        self._counts = dict(prepared_cases=0, selected_cases=0, omitted_cases=0,
                            prepared_variants=0, selected_variants=0)
        self._remaining = {n for n in request.options.selected_cases if n > request.options.skip}
        self._outcome, self._error = 'pending', None
        self._cleanup_errors = ()
        with application._lock:
            if application._closed:
                raise ContractError('application', 'closed', 'application is closed')
            application._preparations[self.preparation_id] = self

    @property
    def summary(self):
        return freeze({**self._counts, 'outcome': self._outcome, 'error': self._error,
                       'missing_cases': tuple(sorted(self._remaining)), 'offered': 0,
                       'cleanup_errors': self._cleanup_errors})

    def __iter__(self):
        return self

    def __next__(self):
        if self._done:
            raise StopIteration
        if not self._execution.acquire(blocking=False):
            raise ContractError('campaign.preparation', 'busy', 'one preparation consumer at a time')
        try:
            return next(self._iterator)
        finally:
            self._execution.release()

    def _rows(self):
        try:
            self.application._validate_transport(self.request.transport)
            self.application._validate_destinations(self.request)
            self._families = self.application._campaign_families(self.request)
            self._families.set_cancelled(self._cancelled.is_set)
            from bytefault.fuzzers.conversation import validate_conversation
            while not self._cancel_requested():
                try:
                    family = next(self._families)
                except StopIteration:
                    break
                resolved = []
                for case in family:
                    if self._cancel_requested():
                        break
                    resolved.append(validate_conversation(case))
                if self._cancel_requested():
                    break
                resolved = tuple(resolved)
                number = family[0].campaign.case_number
                self._counts['prepared_cases'] += 1
                self._counts['prepared_variants'] += len(family)
                self._remaining.discard(number)
                if selected_case(self.request.options, number):
                    if self._cancel_requested():
                        break
                    self._counts['selected_cases'] += 1
                    self._counts['selected_variants'] += len(family)
                    yield freeze({'case_number': number, 'requests': family, 'materialized': resolved,
                                  'application_request':self.request})
                else:
                    self._counts['omitted_cases'] += 1
            self._outcome = 'cancelled' if self._cancel_requested() else (
                'unreached' if self._remaining else 'completed')
        except BaseException as error:
            if not isinstance(error, GeneratorExit):
                self._outcome, self._error = 'failed', str(error)
            raise
        finally:
            self._finish()

    def _cancel_requested(self):
        return self._cancelled.is_set() or self.application._closed

    def _finish(self):
        if self._done:
            return
        errors = []
        # Passive validate_conversation owns no engine observers; only families need closing.
        if self._families is not None:
            try:
                self._families.close()
            except BaseException as error:
                errors.append(('families', error))
        with self.application._lock:
            self.application._preparations.pop(self.preparation_id, None)
        self._done = True
        self._cleanup_errors = tuple(freeze({'owner': owner, 'error': str(error),
            'error_type': type(error).__name__}) for owner, error in errors)
        if errors:
            primary = sys.exc_info()[1]
            if self._outcome in ('pending', 'completed'):
                self._outcome = 'cleanup_failed'
            if primary is not None and not isinstance(primary, GeneratorExit):
                for owner, error in errors:
                    primary.add_note('Campaign inspection cleanup ' + owner + ': ' + str(error))
            else:
                raise errors[0][1]
        if self._outcome == 'pending':
            self._outcome = 'cancelled'

    def close(self):
        self._cancelled.set()
        if not self._execution.acquire(blocking=False):
            return
        try:
            self._iterator.close()
        finally:
            try:
                self._finish()
            finally:
                self._execution.release()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
