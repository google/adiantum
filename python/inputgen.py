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

import random

def repeatedbyte(l, b):
    return bytes(b for _ in range(l))

def oneset(l, b):
    l = bytearray(l)
    l[b >> 3] |= (1 << (b & 7))
    return bytes(l)

def rangeset(l, s):
    return bytes((b & 0xff) for b in range(s, s+l))

def randbytes(l, r):
    return bytes(r.randrange(0x100) for _ in range(l))

def set_containing(hi, c):
    r = random.Random(repr((hi, c)))
    s = set([0, hi-1])
    while len(s) < c:
        s.add(r.randrange(hi))
    return sorted(s)

def onesets(l, c):
    for i in set_containing(l*8, c):
        yield i, oneset(l, i)

example_count = 12

def generate_onebit(lengths):
    starting = {k: bytes(v) for k, v in lengths.items()}
    for k, v in lengths.items():
        if v*8 < example_count:
            continue
        for i, newv in onesets(v, example_count):
            d = starting.copy()
            d[k] = newv
            yield d, f"Set bit {i} of {k}"

def generate_repeated(lengths):
    for r in set_containing(1<<(len(lengths)*8), example_count):
        values = {k:((r>>(8*i))&0xff) for i, k in enumerate(lengths)}
        d = {k:bytes([values[k]])*v for k,v in lengths.items()}
        yield d, "Repeated bytes: {}".format(" ".join(
            f"{k}: 0x{v:02x}" for k, v in values.items()))

def generate_ranges(lengths):
    starting = {k: bytes(v) for k, v in lengths.items()}
    for k, v in lengths.items():
        if v < 1:
            continue
        for i in set_containing(0x100, example_count):
            d = starting.copy()
            d[k] = rangeset(v, i)
            yield d, f"Incrementing bytes from 0x{i:02x} for {k}"

def generate_random(lengths):
    for i in range(1, example_count +1):
        r = random.Random(repr((lengths, i)))
        d = {k:randbytes(v, r) for k,v in lengths.items()}
        yield d, f"Random ({i:2})"

def generate_testinputs(lengths):
    yield from generate_onebit(lengths)
    yield from generate_ranges(lengths)
    yield from generate_repeated(lengths)
    yield from generate_random(lengths)
