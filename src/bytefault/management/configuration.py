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

"""Shared callable/CLI service configuration, without constructing transports."""
from dataclasses import dataclass
from bytefault.core.contracts import ContractError


@dataclass(frozen=True)
class ServiceConfiguration:
    result_root: str | None = None
    ssh_key: str | None = None
    ssh_user: str | None = None
    ssh_pass: str | None = None
    remote_dir: str = '/root/cores'
    cache_dir: str | None = None
    max_file_size_mb: int = 0
    min_timeout: int = 30
    core_write_wait: float = 5.0
    heartbeat: bool = False
    heartbeat_interval: float = 2.0

    def __post_init__(self):
        from bytefault.monitoring.configuration import number
        for name in ('result_root', 'ssh_key', 'cache_dir'):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value):
                raise ContractError('services.' + name, 'invalid', 'nonempty path or None required')
        for name in ('ssh_user', 'ssh_pass', 'remote_dir'):
            if name != 'remote_dir' and getattr(self, name) is None:
                continue
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ContractError('services.' + name, 'invalid', 'nonempty string required')
        if self.ssh_key is not None and self.ssh_pass is not None:
            raise ContractError('services.ssh_pass', 'conflicting_input', 'key and password authentication conflict')
        if self.ssh_pass is not None and self.ssh_user is None:
            raise ContractError('services.ssh_user', 'required', 'password authentication requires an explicit SSH user')
        for name in ('max_file_size_mb', 'min_timeout'):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ContractError('services.' + name, 'invalid', 'nonnegative integer required')
        number(self.core_write_wait, 'services.core_write_wait')
        if type(self.heartbeat) is not bool:
            raise ContractError('services.heartbeat', 'invalid', 'boolean required')
        number(self.heartbeat_interval, 'services.heartbeat_interval')
        if self.heartbeat_interval == 0:
            raise ContractError('services.heartbeat_interval', 'invalid', 'positive interval required')
