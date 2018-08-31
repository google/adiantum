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

import hbsh
import nh
import poly1305

class HPolyNHC(hbsh.HBSH):
    def _setup_variant(self):
        super()._setup_variant()
        self._nh = nh.NH()

    def _setup_key(self, key):
        self._stream_key = key
        r, self._block_key, self._nh_key = self._setup_key_helper(
            [16, 32, self._nh.lengths()["key"]])
        self._polyr = poly1305.read_r(r)

    def _hash(self, tweak, msg):
        tohash = (8*len(tweak)).to_bytes(8, byteorder='little')
        tohash += (8*len(msg)).to_bytes(8, byteorder='little')
        tohash += tweak
        tohash += b'\0' * (-len(tohash) % 16)
        il = self._nh.lengths()
        msg += b'\0' * (-len(msg) % il['unit'])
        tohash += b"".join(self._nh.nh(self._nh_key, msg[i:i + il['messagemax']])
            for i in range(0, len(msg), il['messagemax']))
        return poly1305.poly1305_h_rbar(self._polyr, tohash)

    def test_input_lengths(self):
        for tlen in 0, 12, 17:
            for mlen in 16, 31, 128, 512:
                for m in "plaintext", "ciphertext":
                    yield {"key": 32, "tweak": tlen, m: mlen}
