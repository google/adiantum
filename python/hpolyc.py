# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

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
