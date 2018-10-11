# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import paths

def parse_tvs():
    p = paths.top / "test_vectors" / "other" / "aes"
    for fn in p.iterdir():
        print(f"======== {fn.name} ========")
        stanza = ""
        with fn.open() as f:
            d = {}
            for l in f:
                l = l.strip()
                if not l or l[0] in "#[":
                    if d:
                        d.update(file=fn.name, stanza=stanza)
                        yield d
                    d = {}
                    if l.startswith("["):
                        stanza = l
                else:
                    k, v = l.split("=", 1)
                    d[k.strip()] = v.strip()
            if d:
                d.update(file=fn.name, stanza=stanza)
                yield d

def test_vectors(x):
    for d in parse_tvs():
        bd = {k: bytes.fromhex(d[k]) for k in ["KEY", "PLAINTEXT", "CIPHERTEXT"]}
        x.set_keylen(len(bd["KEY"]))
        yield {
            'cipher': x.variant,
            'description': f"{d['file']} {d['stanza']} {d['COUNT']}",
            'input': {'key': bd['KEY']},
            'plaintext': bd['PLAINTEXT'],
            'ciphertext': bd['CIPHERTEXT'],
        }

def run_test():
    x = aes.AES()
    for r in test_vectors(x):
        x.check_testvector(r)

if __name__ == "__main__":
    run_test()
