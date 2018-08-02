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

import Crypto.Cipher.AES

import cipher

class AES(cipher.Blockcipher):
    def set_keylen(self, k):
        self.choose_variant(lambda v: v["lengths"]["key"] == k)

    def variant_name(self):
        l = self.variant['lengths']
        return "{}{}".format(self.name(), l['key'] * 8)

    def variants(self):
        for kl in [16, 24, 32]:
            yield {
                'cipher': 'AES',
                'lengths': {
                    'block': 16,
                    'key': kl
                }
            }

    def encrypt(self, pt, key):
        assert len(key) == self.variant['lengths']['key']
        a = Crypto.Cipher.AES.new(key)
        return a.encrypt(pt)

    def decrypt(self, ct, key):
        assert len(key) == self.variant['lengths']['key']
        a = Crypto.Cipher.AES.new(key)
        return a.decrypt(ct)
