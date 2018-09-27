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
import poly1305

class HPolyC(hbsh.HBSH):
    def _setup_key(self, key):
        self._stream_key = key
        self._block_key, r = self._setup_key_helper([32, 16])
        self._polyr = poly1305.read_r(r)

    def _hash(self, tweak, msg):
        header = (8*len(tweak)).to_bytes(4, byteorder='little') + tweak
        padding = b'\0' * (-len(header) % 16)
        return poly1305.poly1305_h_rbar(self._polyr, header + padding + msg)
