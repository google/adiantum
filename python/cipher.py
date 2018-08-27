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

import copy

class Cipher(object):
    def copy(self): return copy.deepcopy(self)

    def name(self):
        return type(self).__name__

    @property
    def variant(self):
        return self._variant

    def _setup_variant(self):
        pass

    @variant.setter
    def variant(self, value):
        if value not in self.variants():
            raise Exception(f"Not a variant: {value}")
        self._variant = value
        self._setup_variant()

    def choose_variant(self, criterion):
        for v in self.variants():
            if criterion(v):
                self.variant = v
                return
        raise Exception("No variant matching criterion")

    def test_input_lengths(self):
        yield self.variant["lengths"]

class ARXCipher(Cipher):
    def _to_ints(self, b):
        assert len(b) % self._word_bytes == 0
        l = len(b) // self._word_bytes
        return [int.from_bytes(b[i:i + self._word_bytes], byteorder=self._byteorder)
            for i in range(0, l * self._word_bytes, self._word_bytes)]

    def _from_ints(self, ints):
        return b''.join(i.to_bytes(self._word_bytes, byteorder=self._byteorder) for i in ints)

    def _mod(self, i):
        return i & ((1 << (self._word_bytes * 8))-1)

    def _rotl(self, i, r):
        return self._mod((i << r) | (i >> (self._word_bytes * 8 - r)))

    def _rotr(self, i, r):
        return self._mod((i >> r) | (i << (self._word_bytes * 8 - r)))

class Blockcipher(Cipher):
    def make_testvector(self, input, description):
        input = input.copy()
        if "plaintext" in input:
            pt = input["plaintext"]
            del input["plaintext"]
            ct = self.encrypt(pt, **input)
        else:
            ct = input["ciphertext"]
            del input["ciphertext"]
            pt = self.decrypt(ct, **input)
        return {
            "cipher": self.variant,
            "description": description,
            "input": input,
            "plaintext": pt,
            "ciphertext": ct,
        }

    def check_testvector(self, tv):
        self.variant = tv["cipher"]
        assert tv["ciphertext"] == self.encrypt(tv["plaintext"], **tv["input"])
        assert tv["plaintext"] == self.decrypt(tv["ciphertext"], **tv["input"])

    def test_input_lengths(self):
        v = self.variant['lengths']
        for m in "plaintext", "ciphertext":
            yield {'key': v['key'], m: v['block']}
