# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import cipher
import nh
import poly1305

class NHPoly1305(cipher.Cipher):
    def __init__(self):
        super().__init__()
        self._nh = nh.NH()
        self._poly1305 = poly1305.Poly1305()

    def variant_name(self):
        return self.name()

    def variants(self):
        yield {
            'cipher': 'NHPoly1305',
            'lengths': {
                'key': 16 + self._nh.lengths()['key'],
                'output': 16,
            }
        }

    def make_testvector(self, input, description):
        return {
            'cipher': self.variant,
            'description': description,
            'input': input,
            'hash': self.nhpoly1305(**input),
        }

    def check_testvector(self, tv):
        self.variant = tv['cipher']
        assert tv['hash'] == self.nhpoly1305(**tv['input'])

    def test_input_lengths(self):
        v = dict(self.lengths())
        il = self._nh.lengths()
        munit = il['unit']
        mmax = il['messagemax']
        del v["output"]
        for mlen in 0, munit, mmax, mmax + munit, 2 * mmax:
            yield {**v, "message": mlen}

    def nhpoly1305(self, key, message):
        mmax = self._nh.lengths()['messagemax']
        nh_hashes = b"".join(self._nh.nh(key[16:], message[i:i + mmax])
                             for i in range(0, len(message), mmax))
        return self._poly1305.mac(nh_hashes, b"", key[:16])
