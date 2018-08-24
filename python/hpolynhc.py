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
        tohash = (8*len(msg)).to_bytes(8, byteorder='little')
        tohash += (8*len(tweak)).to_bytes(8, byteorder='little')
        bulk = msg + tweak
        nl = self._nh.lengths()
        il = nl["message"]
        while len(bulk) > nl["hash"]:
            inp = bulk[:il]
            inp += b'\0' * (il - len(inp))
            tohash += self._nh.nh(self._nh_key, inp)
            bulk = bulk[il:]
        tohash += bulk
        return poly1305.poly1305_h_rbar(self._polyr, tohash)
