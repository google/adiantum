# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import aes
import bachata
import hpolyc
import latindance
import adiantum
import nh
import nhpoly1305
import poly1305
import xconstruct

common_ciphers = [
    latindance.Salsa20(),
    xconstruct.XConstruct(latindance.Salsa20()),
    latindance.ChaCha(),
    latindance.ChaCha20RFC(),
    xconstruct.XConstruct(latindance.ChaCha()),
    poly1305.Poly1305(),
]

our_test_ciphers = common_ciphers + [
    hpolyc.HPolyC(),
    bachata.Bachata(),
    adiantum.Adiantum(),
    nh.NH(),
    nhpoly1305.NHPoly1305(),
]

all_ciphers = our_test_ciphers + [
    aes.AES()
]
