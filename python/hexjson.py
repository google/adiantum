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
