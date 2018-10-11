# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import json
import paths

def test_vectors(ch):
    with (paths.top / "test_vectors" / "other" / "poly1305.json").open() as f:
        for t in json.load(f):
            message = b''.join(bytes.fromhex(l) for l in t["m"])
            yield {
                'cipher': ch.variant,
                'description': f"Message of length {len(message)}",
                'input': {
                    'key': bytes.fromhex(t["r"]),
                    'mask': bytes.fromhex(t["AESkn"]),
                    'message': message,
                },
                'mac': bytes.fromhex(t["mac"]),
            }
