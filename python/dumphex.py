# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

def groupto(it, l):
    res = []
    for i in it:
        res.append(i)
        if len(res) == l:
            yield res
            res = []
    if res:
        yield res

def dumphex(b):
    for i, l in enumerate(groupto(b, 16)):
        print(f"{i*16:8x} {' '.join(f'{e:02x}' for e in l)}")
