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

"""bytefault.fuzzers — public API re-exports.

Import commonly used symbols from their canonical modules. Both
``from bytefault.fuzzers import X`` and
``from bytefault.fuzzers.fuzzer import X`` remain available.
"""

# These exports also serve protocol and callable integrations outside the
# bundled Raw directory; current in-tree usage is not their removal criterion.
from bytefault.fuzzers.byte_mask import ByteMask  # noqa: F401
from bytefault.fuzzers.helpers import (  # noqa: F401
    parse_hex_bytes,
    parse_hex_byte,
    _parse_length_range,
    _parse_recovery_delays,
    _load_seed_file,
    _field_sizes_from_schema,
    _int_to_bytes,
    _field_default_lens_from_schema,
)
from bytefault.fuzzers.packet_builder import (  # noqa: F401
    PacketBuilder,
    _apply_computed_fields,
    _apply_length_field,
    _apply_checksum_field,
    _apply_offset_injections,
    _length_spec_from_schema,
    _computed_specs_from_schema,
    _sequence_specs_from_schema,
    _field_offsets_from_schema,
)
from bytefault.fuzzers.fuzzer import ProtocolFuzzer  # noqa: F401
from bytefault.fuzzers.session_mixin import SessionMixin  # noqa: F401
