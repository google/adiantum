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

import latindance

# Just for fun, I turned the 64-bit ChaCha variant used in BLAKE2b
# into a stream cipher

class Bachata(latindance.ChaCha):
    _word_bytes = 8
    _constant = "expand {0[lengths][key]:2}-byte key thru {0[rounds]:2} round"

    _positions = {
        "const": list(range(4)),
        "key": list(range(4,8)),
        "offset": [8],
        "nonce": list(range(9,16)),
    }
    _positions["nonceoffset"] = _positions["offset"] + _positions["nonce"]

    _rotls = [32, 24, 16, 63]
