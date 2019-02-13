# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import hbsh
import nh
import poly1305

class Adiantum(hbsh.HBSH):
    def _setup_variant(self):
        super()._setup_variant()
        self._nh = nh.NH()

    def _setup_key(self, key):
        self._stream_key = key
        self._block_key, rt, rm, self._nh_key = self._setup_key_helper(
            [32, 16, 16, self._nh.lengths()["key"]])
        self._polyrt = poly1305.read_r(rt)
        self._polyrm = poly1305.read_r(rm)

    def _hash(self, tweak, msg):
        ht = poly1305.poly1305_h_rbar(self._polyrt,
            (8*len(msg)).to_bytes(16, byteorder='little') + tweak)
        il = self._nh.lengths()
        msg += b'\0' * (-len(msg) % il['unit'])
        hm = poly1305.poly1305_h_rbar(self._polyrm,
            b"".join(self._nh.nh(self._nh_key, msg[i:i + il['messagemax']])
                for i in range(0, len(msg), il['messagemax'])))
        return ht + hm
