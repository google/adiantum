# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import paths

def parse():
    d = {}
    with (paths.top / "test_vectors" / "other" / "xsalsa20.txt").open() as f:
        for l in f:
            l = l.strip()
            if l:
                k, v = l.strip().split("=", 1)
                d[k] = v
            elif d:
                yield d
                d = {}
    yield d

def test_vectors(x):
    for d in parse():
        bd = {k: bytes.fromhex(d[k]) for k in ["KEY", "IV", "PLAINTEXT", "CIPHERTEXT"]}
        x.set_rounds_keylen(20, len(bd["KEY"]))
        yield {
            'cipher': x.variant,
            'description': d['COUNT'],
            'input': {'key': bd["KEY"], 'nonce': bd["IV"]},
            'plaintext': bd["PLAINTEXT"],
            'ciphertext': bd["CIPHERTEXT"],
        }
