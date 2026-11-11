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

"""Owned standalone client disposal, separate from the primary operation result."""
from bytefault.core.contracts import freeze


def finish_owned_application(application, *, primary_error=None):
    facts = []
    try:
        cleanup = application.close()
        if application.management is not None:
            services = application.management.wait()
            cleanup = application.close()
            if services['outcome'] == 'failed':
                facts.append({'owner': 'management', 'status': services})
        if cleanup['outcome'] != 'completed':
            facts.append({'owner': 'application', 'status': cleanup})
    except Exception as error:
        facts.append({'owner': 'application', 'error': str(error), 'error_type': type(error).__name__})
    if facts:
        if primary_error is not None:
            primary_error.add_note('Standalone owner cleanup/follow-up: ' + repr(facts))
        import sys
        try:
            sys.stderr.write('BYTEFAULT STANDALONE CLEANUP/FOLLOWUP FAILURE ' + repr(facts) + '\n')
        except Exception as error:
            facts.append({'owner': 'cleanup_diagnostic', 'error': str(error), 'error_type': type(error).__name__})
    return freeze(tuple(facts))


def with_cleanup(result, facts):
    if not facts:
        return result
    return freeze({**dict(result), 'execution_outcome': result['outcome'],
        'outcome': 'cleanup_failed' if result['outcome'] == 'completed' else result['outcome'],
        'application_cleanup_errors': facts})
