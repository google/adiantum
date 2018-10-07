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
