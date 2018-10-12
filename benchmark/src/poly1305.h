/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "util.h"

#define POLY1305_BLOCK_SIZE	16
#define POLY1305_DIGEST_SIZE	16

struct poly1305_key {
	u32 r[5];	/* base 2^26 */

	/*
	 * r0, r1, 5*r1, r2, 5*r2, r3, 5*r3, r4, 5*r4
	 * for r^1, r^2, r^3, r^4
	 */
	u32 powers[4][9];
};

struct poly1305_state {
	u32 h[5];	/* base 2^26 */
};

void poly1305_setkey(struct poly1305_key *key, const u8 *raw_key);

static inline void poly1305_init(struct poly1305_state *state)
{
	memset(state->h, 0, sizeof(state->h));
}

void poly1305_blocks_generic(const struct poly1305_key *key,
			     struct poly1305_state *state,
			     const u8 *data, size_t nblocks, u32 hibit);

void poly1305_emit_generic(struct poly1305_state *state, le128 *out);

#undef HAVE_POLY1305_SIMD
#ifdef __arm__
#define HAVE_POLY1305_SIMD 1

extern void poly1305_blocks_neon(u32 h[5], const u8 *inp, size_t len,
				 u32 padbit, const u32 powers[4][9]);
extern void poly1305_emit_neon(u32 h[5], u8 out[16]);

static inline void poly1305_blocks_simd(const struct poly1305_key *key,
					struct poly1305_state *state,
					const void *data, size_t nblocks,
					u32 hibit)
{

	poly1305_blocks_neon(state->h, data, nblocks * POLY1305_BLOCK_SIZE,
			     hibit, key->powers);
}

static inline void poly1305_emit_simd(struct poly1305_state *state, le128 *out)
{
	poly1305_emit_neon(state->h, (u8 *)out);
}
#endif /* __arm__ */

static inline void poly1305_blocks(const struct poly1305_key *key,
				   struct poly1305_state *state,
				   const void *data, size_t nblocks, u32 hibit,
				   bool simd)
{
#ifdef HAVE_POLY1305_SIMD
	if (simd) {
		poly1305_blocks_simd(key, state, data, nblocks, hibit);
		return;
	}
#endif
	poly1305_blocks_generic(key, state, data, nblocks, hibit << 24);
}

static inline void poly1305_tail(const struct poly1305_key *key,
				 struct poly1305_state *state,
				 const void *src, size_t srclen, bool simd)
{
	poly1305_blocks(key, state, src, srclen / POLY1305_BLOCK_SIZE, 1, simd);

	if (srclen % POLY1305_BLOCK_SIZE) {
		u8 block[POLY1305_BLOCK_SIZE];

		src += srclen - (srclen % POLY1305_BLOCK_SIZE);
		srclen %= POLY1305_BLOCK_SIZE;
		memcpy(block, src, srclen);
		block[srclen++] = 1;
		memset(&block[srclen], 0, sizeof(block) - srclen);
		poly1305_blocks(key, state, block, 1, 0, simd);
	}
}

static inline void poly1305_emit(struct poly1305_state *state, le128 *out,
				 bool simd)
{
#ifdef HAVE_POLY1305_SIMD
	if (simd) {
		poly1305_emit_simd(state, out);
		return;
	}
#endif
	poly1305_emit_generic(state, out);
}
