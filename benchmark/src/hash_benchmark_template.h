/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
{
	const size_t bufsize = g_params.bufsize;
	u8 *data = malloc(bufsize);
	u8 digest[DIGEST_SIZE];
#ifdef HASH_SIMD
	u8 digest_simd[DIGEST_SIZE];
#endif
#if KEY_BYTES != 0
	u8 key[KEY_BYTES];
	KEY ctx;
#endif
	unsigned long i;
	int try;
	const int ntries = g_params.ntries;
	const unsigned long nbytes = round_up(1000000, bufsize);
	u64 start;
	u64 best_time;

	rand_bytes(data, bufsize);

#if KEY_BYTES != 0
	rand_bytes(key, sizeof(key));
	SETKEY(&ctx, key);
#endif

	best_time = UINT64_MAX;
	for (try = 0; try < ntries; try++) {
		start = now();
		for (i = 0; i < nbytes; i += bufsize)
			HASH(&ctx, data, bufsize, digest);
		best_time = min(best_time, now() - start);
	}
	show_result(ALGNAME, "hashing", "generic", nbytes, best_time);

#ifdef HASH_SIMD
	best_time = UINT64_MAX;
	for (try = 0; try < ntries; try++) {
		start = now();
		for (i = 0; i < nbytes; i += bufsize)
			HASH_SIMD(&ctx, data, bufsize, digest_simd);
		best_time = min(best_time, now() - start);
		ASSERT(!memcmp(digest, digest_simd, DIGEST_SIZE));
	}
	show_result(ALGNAME, "hashing", SIMD_IMPL_NAME, nbytes, best_time);
#endif
	putchar('\n');

	free(data);
}

#undef ALGNAME
#undef KEY_BYTES
#undef KEY
#undef SETKEY
#undef HASH
#undef HASH_SIMD
