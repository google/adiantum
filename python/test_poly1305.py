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
