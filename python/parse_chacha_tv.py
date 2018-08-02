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

import re

import paths
import parsetv

class ParseChacha20(parsetv.ParseTv):
    def _finish_tvkv(self):
        if self._tvvalue:
            m = re.fullmatch(r"Keystream block (\d+)", self._tvkey)
            if m:
                self._tvstreamlist.append({
                    "block": int(m.group(1)),
                    "value": self._tvvalue,
                })
            else:
                self._tvdict[self._tvkey] = self._tvvalue
        self._tvkey = None
        self._tvvalue = None

    def _handle_line(self, l):
        l = l.strip()
        if l.startswith("Test vectors"):
            pass
        elif len(l) == 0:
            self._finish_tvkv()
        elif l[0] in "=-":
            pass
        elif l.startswith("TC"):
            self._start_tvset({"setintro": l})
        elif ":" in l:
            k, v = l.split(":", 1)
            if k == "Key":
                self._start_tv({})
            self._start_tvkv(k.strip())
            self._vappend(v.strip())
        else:
            self._vappend(l)

def test_vectors():
    p = ParseChacha20()
    p.parse_file(paths.top / "test_vectors" / "other" / "chacha_testvectors.txt")
    return p.get()
