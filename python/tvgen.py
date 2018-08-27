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

import hexjson

import inputgen

def generate_testvectors(cipher):
    for lengths in cipher.test_input_lengths():
        print(lengths)
        for tv, d in inputgen.generate_testinputs(lengths):
            yield cipher.make_testvector(tv, d)

def write_tests(cipher, path):
    d = path / cipher.name()
    for v in cipher.variants():
        cipher.variant = v
        p = d / "{}.json".format(cipher.variant_name())
        print(f"Writing: {p}")
        hexjson.write_using_hex(p, generate_testvectors(cipher))

def check_testvector(cipher, tv, verbose):
    cipher.check_testvector(tv)
    if verbose:
        print(f"OK: {tv['description']}")

def check_tests(cipher, path, verbose):
    for fn in (path / cipher.name()).iterdir():
        print(f"======== {fn.name} ========")
        for tv in hexjson.iter_unhex(fn):
            check_testvector(cipher, tv, verbose)
