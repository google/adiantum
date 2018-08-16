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

# Copied from https://tools.ietf.org/html/rfc7539

key = ("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:" +
       "14:15:16:17:18:19:1a:1b:1c:1d:1e:1f")
nonce = "00:00:00:00:00:00:00:4a:00:00:00:00"

ptext = """
  000  4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c  Ladies and Gentl
  016  65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73  emen of the clas
  032  73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63  s of '99: If I c
  048  6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f  ould offer you o
  064  6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20  nly one tip for
  080  74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73  the future, suns
  096  63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69  creen would be i
  112  74 2e                                            t.
"""

ctext = """
  000  6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81  n.5.%h..A..(..i.
  016  e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b  .~z..C`..'......
  032  f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57  ..e.RG3..Y=..b.W
  048  16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8  .9.$.QR..S.5..a.
  064  07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e  ....P.jaV....".^
  080  52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36  R.QM.........y76
  096  5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42  Z...t.[......x^B
  112  87 4d                                            .M
"""

def parse_colonhex(ch): return bytes.fromhex(ch.replace(":", ""))

def parse_blockhexline(bhl):
    if len(bhl) < 9: return b''
    return bytes.fromhex(bhl[7:7+16*3].replace(" ", ""))

def parse_blockhex(bh):
    return b''.join(parse_blockhexline(bhl) for bhl in bh.split("\n"))

def test_vectors(ch):
    k = parse_colonhex(key)
    ch.set_rounds_keylen(20, len(k))
    yield {
        'cipher': ch.variant,
        'description': "From RFC",
        'input': {'key': k, 'nonce': parse_colonhex(nonce), 'offset': 1},
        'plaintext': parse_blockhex(ptext),
        'ciphertext': parse_blockhex(ctext),
    }
