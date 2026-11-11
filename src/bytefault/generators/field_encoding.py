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

"""Named candidate encoding; field widths never restrict packet admission."""
from bytefault.generators.iterator import IteratorGenerator


def field_width(field, field_sizes, field_default_lens, base_values):
    size = field_sizes.get(field, 'var')
    if size not in (None, 'var'):
        return int(size)
    return max(1, len(base_values.get(field, b'')) or field_default_lens.get(field) or 1)


def padded_base(field, base_values, field_sizes, pad_byte):
    data = base_values.get(field, b'')
    size = field_sizes.get(field, 'var')
    return (bytes([pad_byte]) * max(0, int(size) - len(data)) + data
            if size not in (None, 'var') else data)


def encode_field(data, *, width, base=b'', fill=False, mode='leading', endian='big', pad_byte=0):
    if type(width) is not int or width < 0 or type(base) is not bytes or type(fill) is not bool:
        raise ValueError('nonnegative field width, exact base bytes and boolean fill required')
    if mode not in ('leading', 'integer', 'pad'):
        raise ValueError('leading, integer or pad field encoding required')
    if endian not in ('big', 'little'):
        raise ValueError('big or little field endian required')
    if type(pad_byte) is not int or not 0 <= pad_byte <= 255:
        raise ValueError('padding value must be a byte')
    if mode == 'pad':
        return bytes([pad_byte]) * max(0, width - len(data)) + data
    value = int.from_bytes(data, endian)
    if fill:
        return bytes([value & 255]) * width
    minimum = max(1, (value.bit_length() + 7) // 8)
    if mode == 'integer':
        return value.to_bytes(max(width, minimum), endian)
    leading = max(width, minimum) if minimum > 2 else minimum
    return value.to_bytes(leading, 'big') + base[leading:max(width, len(base))]


# Retained named-field generator facade for callable/schema integrations;
# it shares encode_field with current transforms rather than a separate encoder.
class FieldByteGenerator(IteratorGenerator):
    """Retained pure helper caller sharing the current attributed encoder."""
    def __init__(self, mask, width, base_bytes, fill=False, start_value=None):
        super().__init__(mask, width=max(1, width), start_value=start_value)
        self.field_width, self.base_bytes, self.field_fill = width, base_bytes, fill

    def generate(self):
        for value in self._mask.iter_values(self._start_value):
            yield encode_field(value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big'),
                width=self.field_width, base=self.base_bytes, fill=self.field_fill)

    def metadata(self):
        return {'type': 'field_byte_iterator', 'width': self.field_width,
                'fill': self.field_fill, 'total_values': self.count()}
