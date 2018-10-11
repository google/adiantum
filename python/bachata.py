# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

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
