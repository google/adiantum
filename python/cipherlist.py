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

import aes
import bachata
import hpolyc
import latindance
import hpolynhc
import nh
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
    hpolynhc.HPolyNHC(),
    nh.NH(),
]

all_ciphers = our_test_ciphers + [
    aes.AES()
]
