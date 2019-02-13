# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import cipher
import latindance
import xconstruct
import aes

class HBSH(cipher.Blockcipher):
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

    def _stream_xor(self, nonce, m):
        needed = self._stream.lengths()["nonce"]
        padded_nonce = nonce + b'\1' + b'\0' * (needed - len(nonce) -1)
        return self._stream.encrypt(m, key=self._stream_key, nonce=padded_nonce)

    def _setup_key_helper(self, needed):
        km = self._stream_xor(b'', b'\0' * sum(needed))
        return [km[sum(needed[:i]):sum(needed[:i+1])] for i in range(len(needed))]

    def _block_add(self, block, toadd):
        i = int.from_bytes(block, byteorder='little')
        i += toadd
        i &= ((1<<128)-1)
        return i.to_bytes(16, byteorder='little')

    def _block_subtract(self, block, tosubtract):
        return self._block_add(block, -tosubtract)

    def encrypt(self, block, key, tweak):
        self._setup_key(key)
        pl, pr = block[:-16], block[-16:]
        pm = self._block_add(pr, self._hash(tweak, pl))
        cm = self._block.encrypt(pm, key=self._block_key)
        cl = self._stream_xor(cm, pl)
        cr = self._block_subtract(cm, self._hash(tweak, cl))
        return cl + cr

    def decrypt(self, block, key, tweak):
        self._setup_key(key)
        cl, cr = block[:-16], block[-16:]
        cm = self._block_add(cr, self._hash(tweak, cl))
        pl = self._stream_xor(cm, cl)
        pm = self._block.decrypt(cm, key=self._block_key)
        pr = self._block_subtract(pm, self._hash(tweak, pl))
        return pl + pr

    def test_input_lengths(self):
        v = self.lengths()
        for tlen in 0, 17, 32:
            for mlen in 16, 31, 128, 512, 1536, 4096:
                for m in "plaintext", "ciphertext":
                    yield {**v, "tweak": tlen, m: mlen}
