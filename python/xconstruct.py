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

class XConstruct(latindance.Latinlike):
    def __init__(self, delegate):
        self._delegate = delegate
        self._key = None

    def name(self):
        return "X" + self._delegate.name()

    def variant_name(self):
        return "X" + self._delegate.variant_name()

    def variants(self):
        d = self._delegate.copy()
        for v in d.variants():
            d.variant = v
            dhl = d.hash_lengths()
            dl = d.lengths()
            # "Extending the Salsa20 nonce" asserts that Salsa20 takes a 256-bit key, and
            # doesn't specify how a 128-bit key would be handled, so we simply force the
            # key size to be the same as the hash output length here.
            if dhl["output"] == dl["key"]:
                yield {"cipher": self.name(), "rounds": v["rounds"],
                    "delgatevariant": v, "lengths": {
                        "key": dhl["key"], "nonce": dhl["nonceoffset"] + dl["nonce"]}}

    def _setup_variant(self):
        self._delegate.variant = self.variant["delgatevariant"]

    def gen_output(self, key, nonce, offset):
        ks = self._delegate.copy()
        nl = ks.hash_lengths()["nonceoffset"]
        subkey = ks.hash(key=key, nonceoffset=nonce[:nl])
        return self._delegate.gen_output(key=subkey, nonce=nonce[nl:], offset=offset)
