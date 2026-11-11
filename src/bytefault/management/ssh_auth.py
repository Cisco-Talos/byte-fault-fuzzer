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

"""OpenSSH password authentication for Management's local process boundary."""
from pathlib import Path
import os
import sys
import tempfile


def password_authenticated_run(process, command, timeout, password):
    # OpenSSH executes SSH_ASKPASS with the prompt as its only argument.
    # Starting this Python executable loads temporary sitecustomize before
    # Python tries to interpret that prompt as a script path. This works
    # without a platform-specific executable script or password in argv.
    with tempfile.TemporaryDirectory(prefix='bytefault-askpass-') as directory:
        helper = Path(directory) / 'sitecustomize.py'
        helper.write_text('import os, sys\n'
            'sys.stdout.buffer.write(os.environ["BYTEFAULT_SSH_ASKPASS_PASSWORD"].encode())\n'
            'sys.stdout.buffer.flush()\n'
            'os._exit(0)\n',
            encoding='utf-8')
        environment = os.environ.copy()
        inherited_pythonpath = environment.get('PYTHONPATH')
        environment.update(SSH_ASKPASS=sys.executable, SSH_ASKPASS_REQUIRE='force',
            DISPLAY=environment.get('DISPLAY') or ':0',
            PYTHONPATH=directory + (os.pathsep + inherited_pythonpath if inherited_pythonpath else ''),
            BYTEFAULT_SSH_ASKPASS_PASSWORD=password)
        return process(command, capture_output=True, text=True, timeout=timeout,
            env=environment)
