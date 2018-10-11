# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import json

def groupto(n, x):
    res = []
    for i in x:
        res.append(i)
        if len(res) == n:
            yield res
            res = []
    if res:
        yield res

def tv_to_rows(tv):
    return [
        ("Key", tv["input"]["key_hex"]),
        ("Tweak", tv["input"]["tweak_hex"]),
        ("Plaintext", tv["plaintext_hex"]),
        ("Ciphertext", tv["ciphertext_hex"]),
    ]

def get_rows(jf):
    with jf.open() as f:
        js = json.load(f)
    done = set()
    for tv in js:
        if not tv["description"].startswith("Random"):
            continue
        tvrows = tv_to_rows(tv)
        lens = tuple(len(e[1]) for e in tvrows)
        if lens in done:
            continue
        yield tvrows
        done.add(lens)

def append_tv(tvrows, f):
    f.write(r"\begin{longtable}{ r | l }" "\n")
    f.write(r"\hline" "\n")
    for k, v in tvrows:
        vb = ["".join(t) for t in groupto(2, v)] # bytes
        g = ["\n    \\texttt{{{}}}".format(" ".join(t))
            for t in groupto(16, vb)] # groups of 16 bytes
        c = " \\\\ ".join(g)
        b = len(vb)
        f.write(f"\\makecell[tr]{{{k} \\\\ {b} bytes}} & \\makecell[tl]{{{c}}} \\\\\n")
    f.write(r"\hline" "\n")
    f.write(r"\end{longtable}" "\n\n")

def write_tvs(jf, tvs):
    with tvs.open("w") as f:
        for tvrows in get_rows(jf):
            append_tv(tvrows, f)

