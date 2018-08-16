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
