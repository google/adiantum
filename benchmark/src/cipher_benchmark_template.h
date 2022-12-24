/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
{
	const size_t bufsize = g_params.bufsize;
	u8 *orig = calloc(1, bufsize);
	u8 *ctext = calloc(1, bufsize);
#ifdef ENCRYPT_SIMD
	u8 *ctext_simd = calloc(1, bufsize);
#endif
	u8 *ptext = calloc(1, bufsize);
	u8 key[KEY_BYTES];
	u8 orig_iv[IV_BYTES];
	u8 iv[IV_BYTES];
	KEY ctx;
	unsigned long i;
	int try;
	const int ntries = g_params.ntries;
	const unsigned long nbytes = round_up(1000000, bufsize);
	u64 start;
	u64 best_time;

	rand_bytes(key, sizeof(key));
	rand_bytes(orig_iv, sizeof(iv));
	rand_bytes(orig, bufsize);

	SETKEY(&ctx, key);

	best_time = UINT64_MAX;
	for (try = 0; try < ntries; try++) {
		memcpy(iv, orig_iv, sizeof(iv));
		start = now();
		for (i = 0; i < nbytes; i += bufsize)
			ENCRYPT(&ctx, ctext, orig, bufsize, iv);
		best_time = min(best_time, now() - start);
	}
	ASSERT(memcmp(orig, ctext, bufsize));
	show_result(ALGNAME, "encryption", "generic", nbytes, best_time);

	best_time = UINT64_MAX;
	for (try = 0; try < ntries; try++) {
		memcpy(iv, orig_iv, sizeof(iv));
		start = now();
		for (i = 0; i < nbytes; i += bufsize)
			DECRYPT(&ctx, ptext, ctext, bufsize, iv);
		best_time = min(best_time, now() - start);
	}
	ASSERT(!memcmp(orig, ptext, bufsize));
	show_result(ALGNAME, "decryption", "generic", nbytes, best_time);

#ifdef ENCRYPT_SIMD
	best_time = UINT64_MAX;
	for (try = 0; try < ntries; try++) {
		memcpy(iv, orig_iv, sizeof(iv));
		start = now();
		for (i = 0; i < nbytes; i += bufsize)
			ENCRYPT_SIMD(&ctx, ctext_simd, orig, bufsize, iv);
		best_time = min(best_time, now() - start);
		ASSERT(memcmp(orig, ctext_simd, bufsize));
		ASSERT(!memcmp(ctext, ctext_simd, bufsize));
	}
	show_result(ALGNAME, "encryption", SIMD_IMPL_NAME, nbytes, best_time);
	best_time = UINT64_MAX;
	for (try = 0; try < ntries; try++) {
		memcpy(iv, orig_iv, sizeof(iv));
		start = now();
		for (i = 0; i < nbytes; i += bufsize)
			DECRYPT_SIMD(&ctx, ptext, ctext_simd, bufsize, iv);
		best_time = min(best_time, now() - start);
		ASSERT(!memcmp(orig, ptext, bufsize));
	}
	show_result(ALGNAME, "decryption", SIMD_IMPL_NAME, nbytes, best_time);
#endif /* ENCRYPT_SIMD */
	putchar('\n');

	free(orig);
	free(ctext);
#ifdef ENCRYPT_SIMD
	free(ctext_simd);
#endif
	free(ptext);
}

#undef ALGNAME
#undef KEY_BYTES
#undef IV_BYTES
#undef KEY
#undef SETKEY
#undef ENCRYPT
#undef DECRYPT
#undef ENCRYPT_SIMD
#undef DECRYPT_SIMD
