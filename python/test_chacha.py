# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import parse_chacha_tv

def parse_0x(v):
    if not v.startswith("0x"):
        raise Exception(f"Not 0x: {v}")
    return bytes.fromhex(v[2:])

def parse_tvhex(h):
    return b''.join(parse_0x(v) for l in h if l for v in l.split(" "))

def test_vectors(ch):
    for r in parse_chacha_tv.test_vectors():
        for vs in r["vectorsets"]:
            for tv in vs["testvectors"]:
                d = tv["dict"]
                k = parse_tvhex(d["Key"])
                rounds = int(" ".join(d["Rounds"]))
                ch.set_rounds_keylen(rounds, len(k))
                yield {
                    'cipher': ch.variant,
                    'description': "{} {} {}".format(
                        vs["setintro"], 8*len(k), rounds),
                    'input': {'key': k, 'nonce': parse_tvhex(d["IV"])},
                    'tests': [{
                            'input': {'offset': kb["block"]},
                            'result': parse_tvhex(kb["value"])}
                        for kb in tv["streams"]],
                }
