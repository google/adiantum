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

import re

def parseperf(fn):
    rexp = re.compile(r"(\S+) (encryption|decryption|hashing) \(\S+\)\s+(\d+\.\d+) cpb")
    for l in fn.open():
        m = rexp.match(l)
        if m:
            yield (m.group(1), m.group(2), float(m.group(3)))

def gen_blockciphers():
    yield from ["NOEKEON", "XTEA"]
    for l in [128, 256]:
        yield from [f"Speck128/{l}", f"AES-{l}"]

def gen_interesting():
    yield from ['NH', 'Poly1305']
    for b in gen_blockciphers():
       yield f"{b}-XTS"
    for r in [8, 12, 20]:
        yield f"ChaCha{r}"
        yield f"HPolyNHC-XChaCha{r}-AES"

interesting = set(gen_interesting())

def readperf(table, bufsize, fn):
    for cipher, dirn, cpb in parseperf(fn):
        if cipher not in interesting:
            continue
        cm = table.setdefault(cipher, {})
        bm = cm.setdefault(dirn, {})
        bm[bufsize] = min(cpb, bm.get(bufsize, cpb))

def rowbounds(entry):
    bounds = {}
    for speeds in entry.values():
        for bufsize, s in speeds.items():
            prev = bounds.get(bufsize, (s, s))
            bounds[bufsize] = (min(s, prev[0]), max(s, prev[1]))
    return bounds

def boundstight(bounds):
    for b in bounds.values():
        if b[0]*1.02 < b[1]:
            return False
    return True

def readperfs(d):
    table = {}
    sizes = ['4096', '512']
    for bufsize in sizes:
        readperf(table, bufsize, d / f"output{bufsize}")
    return table

def summarize(table):
    sizes = ['4096', '512']
    for cipher, entry in table.items():
        bounds = rowbounds(entry)
        if boundstight(bounds):
            yield([bounds[s][1] for s in sizes], cipher, None)
        else:
            for dirn, speeds in entry.items():
                yield ([speeds[s] for s in sizes], cipher, dirn)

def formatperf(target, source):
    perfs = list(summarize(readperfs(source)))
    perfs.sort()
    with target.open("w") as f:
        for speeds, cipher, dirn in perfs:
            if dirn is None:
                entries = [cipher]
            else:
                entries = [f"{cipher} ({dirn})"]
            entries += [f"{s:.1f}" for s in speeds]
            if "XChaCha12" in cipher:
                entries = [f"\\textbf{{{e}}}" for e in entries]
            f.write(" & ".join(entries) + " \\\\\n")

def main():
    import pathlib
    wd = pathlib.Path(__file__).parent.resolve().parent
    formatperf(wd / "work" / "performance.tex", wd / "performance")

if __name__ == "__main__":
    main()
