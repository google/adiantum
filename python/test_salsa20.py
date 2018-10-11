# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import parse_salsa20_tv

def read_hex(s): return bytes.fromhex("".join(s))

def stream(s):
    o = s["first"] // 64
    assert s["first"] == o * 64
    assert s["last"] == (o +1) * 64 -1
    return {
        'input': {'offset': o},
        'result': bytes.fromhex("".join(s["value"]))
    }

def test_vectors(x):
    for r in parse_salsa20_tv.test_vectors():
        for vs in r["vectorsets"]:
            for tv in vs["testvectors"]:
                key = read_hex(tv["dict"]["key"])
                x.set_rounds_keylen(20, len(key))
                yield {
                    'cipher': x.variant,
                    'description': tv['intro'],
                    'input': {'key': key, 'nonce': read_hex(tv["dict"]["IV"])},
                    'tests': [stream(s) for s in tv["streams"]],
                }
