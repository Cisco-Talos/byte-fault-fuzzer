#!/usr/bin/env python3
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

"""Source launcher for Bytefault's public commands."""
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent
if sys.path and Path(sys.path[0]).resolve() == REPO_ROOT:
    sys.path.pop(0)
    sys.modules.pop('bytefault', None)
SRC_PATH = REPO_ROOT / 'src'
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from bytefault.cli import build_parser as _build_parser, resolve_arguments, main

if __name__ == '__main__':
    raise SystemExit(main())
