# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import cipher

class W32(cipher.ARXCipher):
    _word_bytes = 4
    _byteorder = 'little'
w32 = W32()

class W64(cipher.ARXCipher):
    _word_bytes = 8
    _byteorder = 'little'
w64 = W64()

class NH(cipher.Cipher):
    def __init__(self):
        super().__init__()
        self.choose_variant(lambda x: True)

    def variant_name(self):
        return self.name()

    def variants(self):
        yield {
            'cipher': 'NH',
            'passes': 4,
            'word_bytes': w32._word_bytes,
            'stride': 2,
            'unitcount': 64}

    def lengths(self):
        v = self.variant
        unit = v['word_bytes'] * v['stride'] * 2
        return {
            'unit': unit,
            'messagemax': unit * v['unitcount'],
            'key': unit * (v['unitcount'] + v['passes'] - 1),
            'hash': v['word_bytes'] * v['passes']
        }

    def test_input_lengths(self):
        v = self.lengths()
        for l in [v['unit'], v['messagemax'] - v['unit'], v['messagemax']]:
            yield {'key': v['key'], 'message': l}

    def make_testvector(self, input, description):
        return {
            'cipher': self.variant,
            'description': description,
            'input': input,
            'hash': self.nh(**input),
        }

    def check_testvector(self, tv):
        self.variant = tv['cipher']
        assert tv['hash'] == self.nh(**tv['input'])

    def _nhpass(self, key, message):
        stride = self.variant['stride']
        return w64._mod(sum(
                w32._mod(message[j] + key[j])
                * w32._mod(message[j + stride] + key[j + stride])
            for i in range(0, len(message), stride * 2)
            for j in range(i, i + stride)
        ))

    def _nh_vec(self, key, message):
        step = self.variant['stride'] * 2
        return [self._nhpass(key[off:off + len(message)], message)
            for off in range(0, step * self.variant['passes'], step)]

    def nh(self, key, message):
        lengths = self.lengths()
        assert len(message) > 0
        assert len(message) <= lengths['messagemax']
        assert len(message) % lengths['unit'] == 0
        assert len(key) == lengths['key']
        key = w32._to_ints(key)
        message = w32._to_ints(message)
        return w64._from_ints(self._nh_vec(key, message))
