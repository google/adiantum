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

import cipher
import latindance
import xconstruct
import poly1305
import aes

class HPolyC(cipher.Blockcipher):
    def __init__(self):
        self._stream = xconstruct.XConstruct(latindance.ChaCha())

    def variant_name(self):
        return "{}_{}_{}".format(self.name(),
            self._stream.variant_name(),
            self._block.variant_name())

    def _blockciphers(self):
        a = aes.AES()
        a.set_keylen(32)
        return [a]

    def _lookup_block(self, v):
        for b in self._blockciphers():
            if b.variant == v:
                return b
        raise Exception(f"Unknown block cipher: {v}")

    def variants(self):
        for bs in self._blockciphers():
            for s in self._stream.variants():
                yield {
                    "cipher": self.name(),
                    "streamcipher": s,
                    "blockcipher": bs.variant,
                    "lengths": {"key": 32}}

    def _setup_variant(self):
        self._block = self._lookup_block(self.variant['blockcipher'])
        self._stream.variant = self.variant["streamcipher"]

    def _setup_key(self, key):
        self._stream_key = key
        km = self._stream_xor(b'', b'\0' * 48)
        self._polyr = poly1305.read_r(km[:16])
        self._block_key = km[16:]

    def _hash(self, tweak, msg):
        header = (8*len(tweak)).to_bytes(4, byteorder='little') + tweak
        padding = b'\0' * (-len(header) % 16)
        return poly1305.poly1305_h_rbar(self._polyr, header + padding + msg)

    def _block_add(self, block, toadd):
        i = int.from_bytes(block, byteorder='little')
        i += toadd
        i &= ((1<<128)-1)
        return i.to_bytes(16, byteorder='little')

    def _stream_xor(self, nonce, m):
        needed = self._stream.lengths()["nonce"]
        padded_nonce = nonce + b'\1' + b'\0' * (needed - len(nonce) -1)
        return self._stream.encrypt(m, key=self._stream_key, nonce=padded_nonce)

    def encrypt(self, block, key, tweak):
        self._setup_key(key)
        pl, pr = block[:-16], block[-16:]
        pm = self._block_add(pr, self._hash(tweak, pl))
        cm = self._block.encrypt(pm, key=self._block_key)
        cl = self._stream_xor(cm, pl)
        cr = self._block_add(cm, -self._hash(tweak, cl))
        return cl + cr

    def decrypt(self, block, key, tweak):
        self._setup_key(key)
        cl, cr = block[:-16], block[-16:]
        cm = self._block_add(cr, self._hash(tweak, cl))
        pl = self._stream_xor(cm, cl)
        pm = self._block.decrypt(cm, key=self._block_key)
        pr = self._block_add(pm, -self._hash(tweak, pl))
        return pl + pr

    def test_input_lengths(self):
        v = self.lengths()
        for tlen in 0, 12, 17:
            for mlen in 16, 31, 128:
                for m in "plaintext", "ciphertext":
                    yield {**v, "tweak": tlen, m: mlen}
