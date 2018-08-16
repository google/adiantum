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
