/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

void test_adiantum(void);
void test_aes(void);
void test_chacha(void);
void test_chacha_mem(void);
void test_cham(void);
void test_chaskey_lts(void);
void test_hpolyc(void);
void test_lea(void);
void test_nh(void);
void test_noekeon(void);
void test_poly1305(void);
void test_rc5(void);
void test_rc6(void);
void test_speck(void);
void test_xtea(void);

struct cipherbench_params {
	int bufsize;
	int ntries;
};

extern struct cipherbench_params g_params;
