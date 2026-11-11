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

"""Payload generators for fuzzing.

Generator hierarchy
-------------------
FuzzGenerator (ABC)
  ├── IteratorGenerator     - iterate ByteMask values
  ├── RandomBytesGenerator  - random-length byte strings
  ├── MutatorGenerator      - mutate seed payloads
  ├── ListGenerator         - yield from pre-computed list
  ├── EdgeCaseGenerator     - boundary/corner-case values
  └── FileGenerator         - one exact whole file by default; explicit binary records

Low-level:
  Mutator - core mutation engine (no FuzzGenerator interface)
"""

from bytefault.generators.base import FuzzGenerator
from bytefault.generators.edge_case import EdgeCaseGenerator
from bytefault.generators.file_gen import FileGenerator
from bytefault.generators.iterator import IteratorGenerator
from bytefault.generators.list_gen import ListGenerator
from bytefault.generators.mutator import Mutator, MutatorGenerator
from bytefault.generators.random_bytes import RandomBytesGenerator
from bytefault.generators.sweep import SweepGenerator
from bytefault.generators.sources import SourceSpec, SourceStream, SourceCandidate, open_source
from bytefault.generators.transforms import TransformSpec, MutationPipeline, TransformationOutcome, PreparationDisposition

__all__ = [
    "EdgeCaseGenerator",
    "FileGenerator",
    "FuzzGenerator",
    "IteratorGenerator",
    "ListGenerator",
    "Mutator",
    "MutatorGenerator",
    "RandomBytesGenerator",
    "SweepGenerator",
    "SourceSpec", "SourceStream", "SourceCandidate", "open_source",
    "TransformSpec", "MutationPipeline", "TransformationOutcome", "PreparationDisposition",
]
