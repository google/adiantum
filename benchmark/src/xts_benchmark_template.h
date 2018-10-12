/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
{
	char xts_algname[strlen(ALGNAME) + 5];
	const size_t bufsize = g_params.bufsize;
	u8 *orig = malloc(bufsize);
	u8 *ctext = malloc(bufsize);
#ifdef XTS_ENCRYPT_SIMD
	u8 *ctext_simd = malloc(bufsize);
#endif
	u8 *ptext = malloc(bufsize);
	u8 block_orig[BLOCK_BYTES];
	u8 block[BLOCK_BYTES];
	u8 key[2 * KEY_BYTES];
	KEY main_key;
	KEY tweak_key;
	unsigned long i, j;
	int try;
	const int ntries = g_params.ntries;
	const unsigned long nbytes = round_up(1000000, bufsize);
	u64 start;
	u64 best_time;
#if BLOCK_BYTES == 16
#  define TWEAK_T	ble128
#  define TWEAK_XOR	ble128_xor
#  define TWEAK_MUL_X	gf128mul_x_ble
#else
#  define TWEAK_T	u64
#  define TWEAK_XOR(dst, src)	*(dst) ^= *(src)
#  define TWEAK_MUL_X(t) *(t) = (*(t) << 1) ^ ((*(t) & (1ULL << 63)) ? 0x1B : 0)
#endif
	TWEAK_T orig_t;
	TWEAK_T t;

	sprintf(xts_algname, "%s-XTS", ALGNAME);

	ASSERT(sizeof(block) == sizeof(t));

	rand_bytes(block_orig, sizeof(block));
	rand_bytes(key, sizeof(key));
	rand_bytes(&orig_t, sizeof(t));
	rand_bytes(orig, bufsize);

	SETKEY(&main_key, &key[0]);
	SETKEY(&tweak_key, &key[KEY_BYTES]);

	ENCRYPT(&main_key, block, block_orig);
	ASSERT(memcmp(block, block_orig, sizeof(block)));
	DECRYPT(&main_key, block, block);
	ASSERT(!memcmp(block, block_orig, sizeof(block)));

	/* XTS encryption (generic) */
	best_time = UINT64_MAX;
	for (try = 0; try < ntries; try++) {
		start = now();
		for (i = 0; i < nbytes; i += bufsize) {
			ENCRYPT(&tweak_key, (u8 *)&t, (u8 *)&orig_t);
			for (j = 0; j < bufsize; j += sizeof(t)) {
				TWEAK_T x;

				memcpy(&x, &orig[j], sizeof(x));
				TWEAK_XOR(&x, &t);
				ENCRYPT(&main_key, (u8 *)&x, (u8 *)&x);
				TWEAK_XOR(&x, &t);
				memcpy(&ctext[j], &x, sizeof(x));
				TWEAK_MUL_X(&t);
			}
		}
		best_time = min(best_time, now() - start);
	}
	ASSERT(memcmp(orig, ctext, bufsize));
	show_result(xts_algname, "encryption", "generic", nbytes, best_time);

	/* XTS decryption (generic) */
	best_time = UINT64_MAX;
	for (try = 0; try < ntries; try++) {
		start = now();
		for (i = 0; i < nbytes; i += bufsize) {
			ENCRYPT(&tweak_key, (u8 *)&t, (u8 *)&orig_t);
			for (j = 0; j < bufsize; j += sizeof(t)) {
				TWEAK_T x;

				memcpy(&x, &ctext[j], sizeof(x));
				TWEAK_XOR(&x, &t);
				DECRYPT(&main_key, (u8 *)&x, (u8 *)&x);
				TWEAK_XOR(&x, &t);
				memcpy(&ptext[j], &x, sizeof(x));
				TWEAK_MUL_X(&t);
			}
		}
		best_time = min(best_time, now() - start);
	}
	ASSERT(!memcmp(orig, ptext, bufsize));
	show_result(xts_algname, "decryption", "generic", nbytes, best_time);

#ifdef XTS_ENCRYPT_SIMD
	best_time = UINT64_MAX;
	for (try = 0; try < ntries; try++) {
		start = now();
		for (i = 0; i < nbytes; i += bufsize) {
			ENCRYPT(&tweak_key, (u8 *)&t, (u8 *)&orig_t);
			XTS_ENCRYPT_SIMD(&main_key, ctext_simd, orig, bufsize,
					 &t);
		}
		best_time = min(best_time, now() - start);
		ASSERT(memcmp(orig, ctext_simd, bufsize));
		ASSERT(!memcmp(ctext, ctext_simd, bufsize));
	}
	show_result(xts_algname, "encryption", SIMD_IMPL_NAME, nbytes,
		    best_time);
	best_time = UINT64_MAX;
	for (try = 0; try < ntries; try++) {
		start = now();
		for (i = 0; i < nbytes; i += bufsize) {
			ENCRYPT(&tweak_key, (u8 *)&t, (u8 *)&orig_t);
			XTS_DECRYPT_SIMD(&main_key, ptext, ctext_simd, bufsize,
					 &t);
		}
		best_time = min(best_time, now() - start);
		ASSERT(!memcmp(orig, ptext, bufsize));
	}
	show_result(xts_algname, "decryption", SIMD_IMPL_NAME, nbytes,
		    best_time);
#endif /* XTS_ENCRYPT_SIMD */
	putchar('\n');

	free(orig);
	free(ctext);
#ifdef XTS_ENCRYPT_SIMD
	free(ctext_simd);
#endif
	free(ptext);
}

#undef TWEAK_T
#undef TWEAK_XOR
#undef TWEAK_MUL_X

#undef ALGNAME
#undef KEY_BYTES
/* #undef BLOCK_BYTES */
/* #undef KEY */
#undef SETKEY
/* #undef ENCRYPT */
/* #undef DECRYPT */
#undef XTS_ENCRYPT_SIMD
#undef XTS_DECRYPT_SIMD
