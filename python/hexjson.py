# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import json

def recursive_hex(o):
    if type(o) == dict:
        res = {}
        for k, v in o.items():
            if k.endswith("_hex"):
                raise Exception(f"Disallowed dict key {k}: we reserve keys that end _hex")
            if type(v) == bytes:
                res[k + "_hex"] = v.hex()
            else:
                res[k] = recursive_hex(v)
        return res
    elif type(o) == list:
        return [recursive_hex(i) for i in o]
    elif type(o) == bytes:
        raise Exception("Can't recursive_hex bytes not contained in dict")
    else:
        return o

def recursive_unhex(o):
    if type(o) == dict:
        res = {}
        for k, v in o.items():
            if k.endswith("_hex"):
                res[k[:-4]] = bytes.fromhex(v)
            else:
                res[k] = recursive_unhex(v)
        return res
    elif type(o) == list:
        return [recursive_unhex(i) for i in o]
    else:
        return o

def write_using_hex(fn, it):
    fn.parent.mkdir(parents=True, exist_ok=True)
    with fn.open("w") as f:
        json.dump([recursive_hex(tv) for tv in it], f, indent=4)

def loadjson(fn):
    with fn.open() as f:
        return json.load(f)

def iter_unhex(fn):
    for htv in loadjson(fn):
        yield recursive_unhex(htv)
