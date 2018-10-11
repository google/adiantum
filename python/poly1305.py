# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import cipher

rclamp =  0xffffffc0ffffffc0ffffffc0fffffff

def read_r(b):
    assert len(b) == 16
    return int.from_bytes(b, byteorder='little') & rclamp

def poly1305_h(r, m):
    return poly1305_h_rbar(int.from_bytes(r, byteorder='little'), m)

def poly1305_h_rbar(rbar, m):
    assert rbar == rbar & rclamp
    h = 0
    p = (1 << 130) - 5
    while len(m) > 0:
        chunk = m[:16]
        c = int.from_bytes(chunk, byteorder='little')
        c += (1 << (8 * len(chunk)))
        m = m[16:]
        h = ((h + c) * rbar) % p
    return h

class Mac(cipher.Cipher):
    def make_testvector(self, input, description):
        return {
            "cipher": self.variant,
            "description": description,
            "input": input,
            "mac": self.mac(**input),
        }

    def check_testvector(self, tv):
        self.variant = tv["cipher"]
        assert tv["mac"] == self.mac(**tv["input"])

    def test_input_lengths(self):
        v = dict(self.lengths())
        del v["output"]
        for mlen in 0, 1, 16, 47:
            yield {**v, "message": mlen}

class Poly1305(Mac):
    def __init__(self):
        super().__init__()
        self.choose_variant(lambda x: True)

    def variant_name(self):
        return self.name()

    def variants(self):
        yield {'cipher': 'Poly1305',
            'lengths': {'key': 16, 'mask': 16, 'output': 16}}

    def mac(self, message, mask, key):
        r = read_r(key)
        mask = int.from_bytes(mask, byteorder='little')
        return (poly1305_h_rbar(r, message) + mask).to_bytes(17, byteorder='little')[:16]
