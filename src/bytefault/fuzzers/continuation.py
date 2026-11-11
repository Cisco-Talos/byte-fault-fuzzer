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

"""Engine-side correlated enforcement; Monitoring chooses policy/conditions."""
import threading
from bytefault.core.validation import validate_wait_obligations
from bytefault.core.contracts import ContractError


class ContinuationGate:
    def __init__(self):
        self.condition = threading.Condition()
        self.hold = None
        self.satisfied = set()
        self.stopped = False
        self.stop_decision = None
        self.stop_cause = None
        self.stop_reason = None
        self.stop_reference = None
        self.deadline = None

    def stop(self, decision=None, *, cause='policy', reason=None, reference=None):
        """Latch the first actual stop; later facts cannot replace its identity."""
        with self.condition:
            if not self.stopped:
                self.stop_decision = decision
                self.stop_cause = cause
                self.stop_reason = reason if reason is not None else (decision.reason if decision else '')
                self.stop_reference = reference
            self.stopped = True
            self.condition.notify_all()

    def select(self, decision, *, now=0):
        # Alternate Monitoring ports must provide the same concrete contract;
        # unresolved/partial waits never reach dispatch or permit advancement.
        validate_wait_obligations(decision)
        with self.condition:
            # A fresh decision can replace a hold only by explicit original
            # correlation; unrelated late work cannot release current testing.
            if self.hold is not None:
                if decision.disposition == 'stop':
                    self.stop(decision, cause='observation_decision')
                elif decision.disposition != 'continue':
                    raise ContractError('monitoring.hold', 'hold_conflict',
                        'new decision cannot replace unresolved hold ' + self.hold.decision_id)
                self.condition.notify_all()
                return
            if decision.disposition == 'stop':
                self.stop(decision, cause='observation_decision')
            elif decision.disposition == 'hold':
                self.hold = decision
                self.satisfied.clear()
                self.deadline = None if decision.hold_timeout is None else now + decision.hold_timeout
            self.condition.notify_all()

    def complete(self, completion):
        with self.condition:
            hold = self.hold
            if hold is None or (completion.decision_id != hold.decision_id or
                    completion.observation_id != hold.observation_id or
                    completion.correlation != hold.correlation or
                    (completion.condition, completion.followup_action_id) not in
                    {(value.condition, value.followup_action_id) for value in hold.obligations}):
                return False
            key = (completion.condition, completion.followup_action_id)
            if completion.status == 'succeeded':
                self.satisfied.add(key)
                if self.satisfied.issuperset((value.condition, value.followup_action_id)
                                            for value in hold.obligations):
                    self.hold = None
                    self.satisfied.clear()
                    self.deadline = None
            else:
                self.satisfied.discard(key)
                if completion.status in ('failed', 'disabled'):
                    self._treatment(hold.on_failure, clear_deadline=hold.on_failure != 'hold',
                        cause='completion_' + completion.status, reference=completion)
            self.condition.notify_all()
            return True

    def _treatment(self, treatment, *, clear_deadline=True, cause='deadline_expiry', reference=None):
        if treatment == 'stop':
            self.stop(self.hold, cause=cause, reference=reference)
        elif treatment == 'advance':
            self.hold = None
            self.satisfied.clear()
        if clear_deadline:
            self.deadline = None
        self.condition.notify_all()

    def expire(self, decision_id):
        with self.condition:
            if self.hold is None or self.hold.decision_id != decision_id:
                return False
            self._treatment(self.hold.on_expiry)
            return True

    def wake(self):
        with self.condition:
            self.condition.notify_all()

    def wait(self, stopped):
        with self.condition:
            while self.hold is not None and not self.stopped and not stopped():
                self.condition.wait(0.05)
            return not self.stopped and not stopped()
