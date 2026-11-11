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

"""Unambiguous JSON value admission shared by directory and argument clients."""
import json

from bytefault.core.contracts import ContractError


def load_json(text, *, path):
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ContractError(path, 'duplicate_field', key)
            value[key] = item
        return value
    try:
        return json.loads(text, object_pairs_hook=unique_object)
    except json.JSONDecodeError as exc:
        raise ContractError(path, 'malformed', str(exc)) from exc
