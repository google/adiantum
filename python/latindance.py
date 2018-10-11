# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import cipher

class Latinlike(cipher.Cipher):
    _tests = [{"offset": o} for o in [0, 1, 1023, 1024, 2048]]

    def variant_name(self):
        return "{0}{1[rounds]}_{1[lengths][key]}".format(self.name(), self.variant)

    def encrypt(self, plaintext, offset=0, **d):
        result = []
        while plaintext:
            stream = self.gen_output(offset=offset, **d)
            offset += 1
            result.append(bytes(x ^ y for x, y in zip(stream, plaintext)))
            plaintext = plaintext[len(stream):]
        return b''.join(result)

    def set_rounds_keylen(self, rounds, keylen):
        self.choose_variant(lambda v: v["rounds"] == rounds and v["lengths"]["key"] == keylen)

    def make_testvector(self, input, description):
        return {
            "cipher": self.variant,
            "description": description,
            "input": input,
            "tests": [dict(input=t, result=self.gen_output(**dict(input, **t)))
                for t in self._tests]
        }

    def check_testvector(self, tv):
        self.variant = tv["cipher"]
        if 'tests' in tv:
            for s in tv["tests"]:
                d = tv["input"].copy()
                d.update(s["input"])
                result = self.gen_output(**d)
                assert result == s["result"]
        elif 'ciphertext' in tv:
            assert tv["ciphertext"] == self.encrypt(tv["plaintext"], **tv['input'])
        else:
            raise Exception("invalid test vector")

class Latindance(Latinlike, cipher.ARXCipher):
    _byteorder = 'little'
    _word_bytes = 4
    _constant = "expand {0[lengths][key]}-byte k"

    def variants(self):
        natural_key_len = self._length("key")
        for r in [8, 12, 20]:
            for k in [natural_key_len // 2, natural_key_len]:
                yield {"cipher": self.name(), "rounds": r, "lengths": {
                    "key": k, "nonce": self._length("nonce")}}

    def _length(self, k):
        return self._word_bytes * len(self._positions[k])

    def _write_initstate(self, d):
        self._initstate = [0] * 16
        for k, v in d.items():
            if len(v) != self._length(k):
                raise Exception("Expected {} bytes for {}, got {}".format(
                    self._length(k), k, len(v)))
            for p, vv in zip(self._positions[k], self._to_ints(v)):
                self._initstate[p] = vv

    def _setup(self, key, **kw):
        if self.lengths()["key"] != self._length("key"):
            key += key
        self._write_initstate(dict(kw,
            const=self._constant.format(self.variant).encode('US-ASCII'), key=key))

    def setup(self, key, nonce, offset):
        self._setup(key, nonce=nonce,
            offset=offset.to_bytes(self._length("offset"), byteorder=self._byteorder))

    def before_rounds(self):
        self._state = self._initstate[:]

    def dump_state(self, decimal=False):
        fmt =  "{:3}" if decimal else "{:02X}"
        for i in range(0, 16, 4):
            print(" ".join("[{}]".format(" ".join(fmt.format((self._state[j] >> k) & 0xff)
                    for k in range(0, self._word_bytes * 8, 8)))
                for j in range(i, i + 4)))
        print()

    def doubleround(self):
        for positions in self._round_positions:
            result = self.quarterround([self._state[p] for p in positions])
            for p, r in zip(positions, result):
                self._state[p] = r

    def apply_rounds(self):
        for i in range(self.variant["rounds"] // 2):
            self.doubleround()

    def _read_state(self, positions):
        return self._from_ints(self._state[i] for i in positions)

    def add_initstate(self):
        for i in range(len(self._state)):
            self._state[i] = self._mod(self._state[i] + self._initstate[i])

    def run(self):
        self.before_rounds()
        self.apply_rounds()
        self.add_initstate()

    def cipher_output(self):
        return self._read_state(range(len(self._state)))

    def gen_output(self, *args, **kw):
        self.setup(*args, **kw)
        self.run()
        return self.cipher_output()

    def hash_lengths(self):
        return {"key": self.lengths()["key"], "nonceoffset": self._length("nonceoffset"),
            "output": self._length("const") + self._length("nonceoffset")}

    def setup_hash(self, key, nonceoffset):
        self._setup(key, nonceoffset=nonceoffset)

    def hash_output(self):
        return self._read_state(self._positions["const"] + self._positions["nonceoffset"])

    def hash(self, *args, **kw):
        self.setup_hash(*args, **kw)
        self.before_rounds()
        self.apply_rounds()
        return self.hash_output()

class Salsa20(Latindance):
    def variant_name(self):
        return "{0}_{1[rounds]}_{1[lengths][key]}".format(self.name(), self.variant)

    _positions = {
        "const": [0, 5, 10, 15],
        "key": [1, 2, 3, 4, 11, 12, 13, 14],
        "nonce": [6, 7],
        "offset": [8, 9],
    }
    _positions["nonceoffset"] = _positions["nonce"] + _positions["offset"]

    _round_positions = [
        [0, 4, 8, 12],
        [5, 9, 13, 1],
        [10, 14, 2, 6],
        [15, 3, 7, 11],
        [0, 1, 2, 3],
        [5, 6, 7, 4],
        [10, 11, 8, 9],
        [15, 12, 13, 14]
    ]

    def quarterround(self, l):
        for i, r in enumerate([7, 9, 13, 18]):
            l[(i+1) % 4] ^= self._rotl(self._mod(l[i] + l[(i+3) % 4]), r)
        return l

class ChaCha(Latindance):
    _positions = {
        "const": list(range(4)),
        "key": list(range(4,12)),
        "nonce": [14, 15],
        "offset": [12, 13],
    }
    _positions["nonceoffset"] = _positions["offset"] + _positions["nonce"]

    _round_positions = [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15],
        [0, 5, 10, 15],
        [1, 6, 11, 12],
        [2, 7, 8, 13],
        [3, 4, 9, 14]
    ]

    _rotls = [16, 12, 8, 7]

    def quarterround(self, l):
        a, b, c, d = tuple(l)
        r = self._rotls
        a = self._mod(a + b); d ^= a; d = self._rotl(d, r[0])
        c = self._mod(c + d); b ^= c; b = self._rotl(b, r[1])
        a = self._mod(a + b); d ^= a; d = self._rotl(d, r[2])
        c = self._mod(c + d); b ^= c; b = self._rotl(b, r[3])
        return [a, b, c, d]

class ChaCha20RFC(ChaCha):
    _positions = ChaCha._positions.copy()
    _positions["nonce"] = [13, 14, 15]
    _positions["offset"] = [12]
    _positions["nonceoffset"] = _positions["offset"] + _positions["nonce"]

    def variants(self):
        yield {"cipher": self.name(), "rounds": 20, "lengths": {
            "key": self._length("key"), "nonce": self._length("nonce")}}
