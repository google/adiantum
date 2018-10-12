/*
 * Poly1305 ε-almost-∆-universal hash function
 *
 * Note: this isn't the full Poly1305 MAC, i.e. it skips the final addition!
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "poly1305.h"

static void poly1305_key_powers(struct poly1305_key *key)
{
	const u32 r0 = key->r[0], r1 = key->r[1], r2 = key->r[2],
		  r3 = key->r[3], r4 = key->r[4];
	const u32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
	u32 h0 = r0, h1 = r1, h2 = r2, h3 = r3, h4 = r4;
	int i = 0;

	for (;;) {
		u64 d0, d1, d2, d3, d4;

		key->powers[i][0] = h0;
		key->powers[i][1] = h1;
		key->powers[i][2] = h1 * 5;
		key->powers[i][3] = h2;
		key->powers[i][4] = h2 * 5;
		key->powers[i][5] = h3;
		key->powers[i][6] = h3 * 5;
		key->powers[i][7] = h4;
		key->powers[i][8] = h4 * 5;

		if (++i == ARRAY_SIZE(key->powers))
			break;

		d0 = ((u64)h0 * r0) + ((u64)h1 * s4) + ((u64)h2 * s3) +
		     ((u64)h3 * s2) + ((u64)h4 * s1);
		d1 = ((u64)h0 * r1) + ((u64)h1 * r0) + ((u64)h2 * s4) +
		     ((u64)h3 * s3) + ((u64)h4 * s2);
		d2 = ((u64)h0 * r2) + ((u64)h1 * r1) + ((u64)h2 * r0) +
		     ((u64)h3 * s4) + ((u64)h4 * s3);
		d3 = ((u64)h0 * r3) + ((u64)h1 * r2) + ((u64)h2 * r1) +
		     ((u64)h3 * r0) + ((u64)h4 * s4);
		d4 = ((u64)h0 * r4) + ((u64)h1 * r3) + ((u64)h2 * r2) +
		     ((u64)h3 * r1) + ((u64)h4 * r0);

		d1 += (u32)(d0 >> 26);
		h0 = d0 & 0x3ffffff;
		d2 += (u32)(d1 >> 26);
		h1 = d1 & 0x3ffffff;
		d3 += (u32)(d2 >> 26);
		h2 = d2 & 0x3ffffff;
		d4 += (u32)(d3 >> 26);
		h3 = d3 & 0x3ffffff;
		h0 += (u32)(d4 >> 26) * 5;
		h4 = d4 & 0x3ffffff;
		h1 += h0 >> 26;
		h0 &= 0x3ffffff;
	}
}

void poly1305_setkey(struct poly1305_key *key, const u8 *raw_key)
{
	/* Clamp the Poly1305 key and split it into five 26-bit limbs */
	key->r[0] = (get_unaligned_le32(raw_key +  0) >> 0) & 0x3ffffff;
	key->r[1] = (get_unaligned_le32(raw_key +  3) >> 2) & 0x3ffff03;
	key->r[2] = (get_unaligned_le32(raw_key +  6) >> 4) & 0x3ffc0ff;
	key->r[3] = (get_unaligned_le32(raw_key +  9) >> 6) & 0x3f03fff;
	key->r[4] = (get_unaligned_le32(raw_key + 12) >> 8) & 0x00fffff;

	/* Precompute key powers */
	poly1305_key_powers(key);
}

void poly1305_blocks_generic(const struct poly1305_key *key,
			     struct poly1305_state *state,
			     const u8 *data, size_t nblocks, u32 hibit)
{
	u32 h0 = state->h[0], h1 = state->h[1], h2 = state->h[2],
	    h3 = state->h[3], h4 = state->h[4];
	const u32 r0 = key->r[0], r1 = key->r[1], r2 = key->r[2],
		  r3 = key->r[3], r4 = key->r[4];
	const u32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
	u64 d0, d1, d2, d3, d4;

	while (nblocks--) {
		/* Invariants: h0, h2, h3, h4 <= 2^26 - 1; h1 <= 2^26 + 63 */

		/*
		 * Add the next message block to 'h' using five 26-bit limbs,
		 * without doing any carries yet.
		 */
		h0 += (get_unaligned_le32(data +  0) >> 0) & 0x3ffffff;
		h1 += (get_unaligned_le32(data +  3) >> 2) & 0x3ffffff;
		h2 += (get_unaligned_le32(data +  6) >> 4) & 0x3ffffff;
		h3 += (get_unaligned_le32(data +  9) >> 6) & 0x3ffffff;
		h4 += (get_unaligned_le32(data + 12) >> 8) | hibit;

		/*
		 * Multiply 'h' by 'r', without carrying, and using the property
		 * 2^130 == 5 (mod 2^130 - 5) to keep within the five limbs:
		 *
		 *     r4       r3       r2       r1       r0
		 *  X  h4       h3       h2       h1       h0
		 *     ------ --------------------------------
		 *     h0*r4    h0*r3    h0*r2    h0*r1    h0*r0
		 *     h1*r3    h1*r2    h1*r1    h1*r0    h1*5*r4
		 *     h2*r2    h2*r1    h2*r0    h2*5*r4  h2*5*r3
		 *     h3*r1    h3*r0    h3*5*r4  h3*5*r3  h3*5*r2
		 *     h4*r0    h4*5*r4  h4*5*r3  h4*5*r2  h4*5*r1
		 *
		 * Even if we assume an unclamped key, the greatest possible sum
		 * of products is in the rightmost column (d0) which can be up
		 * to about 2^57.39.  The least is in the leftmost column (d4)
		 * which can only be up to about 2^55.32.  Thus, the sums fit
		 * well within 64-bit integers.
		 */
		d0 = ((u64)h0 * r0) + ((u64)h1 * s4) + ((u64)h2 * s3) +
		     ((u64)h3 * s2) + ((u64)h4 * s1);
		d1 = ((u64)h0 * r1) + ((u64)h1 * r0) + ((u64)h2 * s4) +
		     ((u64)h3 * s3) + ((u64)h4 * s2);
		d2 = ((u64)h0 * r2) + ((u64)h1 * r1) + ((u64)h2 * r0) +
		     ((u64)h3 * s4) + ((u64)h4 * s3);
		d3 = ((u64)h0 * r3) + ((u64)h1 * r2) + ((u64)h2 * r1) +
		     ((u64)h3 * r0) + ((u64)h4 * s4);
		d4 = ((u64)h0 * r4) + ((u64)h1 * r3) + ((u64)h2 * r2) +
		     ((u64)h3 * r1) + ((u64)h4 * r0);

		/*
		 * Carry h0 => h1 => h2 => h3 => h4 => h0 => h1, assuming no
		 * more than 32 carry bits per limb -- that's guaranteed by all
		 * sums being < 2^58 - 2^32.  d4 is moreover guaranteed to be
		 * < (2^58 - 2^32) / 5, so the needed multiplication with 5 can
		 * be done with 32-bit precision.
		 *
		 * We stop once h1 is reached the second time.  Then, h1 will be
		 * <= 2^26 + 63, and all other limbs will be <= 2^26 - 1.
		 */
		d1 += (u32)(d0 >> 26);
		h0 = d0 & 0x3ffffff;
		d2 += (u32)(d1 >> 26);
		h1 = d1 & 0x3ffffff;
		d3 += (u32)(d2 >> 26);
		h2 = d2 & 0x3ffffff;
		d4 += (u32)(d3 >> 26);
		h3 = d3 & 0x3ffffff;
		h0 += (u32)(d4 >> 26) * 5;
		h4 = d4 & 0x3ffffff;
		h1 += h0 >> 26;
		h0 &= 0x3ffffff;

		data += POLY1305_BLOCK_SIZE;
	}

	state->h[0] = h0;
	state->h[1] = h1;
	state->h[2] = h2;
	state->h[3] = h3;
	state->h[4] = h4;
}

void poly1305_emit_generic(struct poly1305_state *state, le128 *out)
{
	u32 h0 = state->h[0], h1 = state->h[1], h2 = state->h[2],
	    h3 = state->h[3], h4 = state->h[4];
	u32 g0, g1, g2, g3, g4;
	u32 mask;

	/* fully carry h */
	h2 += (h1 >> 26);     h1 &= 0x3ffffff;
	h3 += (h2 >> 26);     h2 &= 0x3ffffff;
	h4 += (h3 >> 26);     h3 &= 0x3ffffff;
	h0 += (h4 >> 26) * 5; h4 &= 0x3ffffff;
	h1 += (h0 >> 26);     h0 &= 0x3ffffff;

	/* compute h + -p */
	g0 = h0 + 5;
	g1 = h1 + (g0 >> 26);             g0 &= 0x3ffffff;
	g2 = h2 + (g1 >> 26);             g1 &= 0x3ffffff;
	g3 = h3 + (g2 >> 26);             g2 &= 0x3ffffff;
	g4 = h4 + (g3 >> 26) - (1 << 26); g3 &= 0x3ffffff;

	/* select h if h < p, or h + -p if h >= p */
	mask = (g4 >> 31) - 1;
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* h = h % (2^128) */
	out->w32[0] = cpu_to_le32((h0 >> 0)  | (h1 << 26));
	out->w32[1] = cpu_to_le32((h1 >> 6)  | (h2 << 20));
	out->w32[2] = cpu_to_le32((h2 >> 12) | (h3 << 14));
	out->w32[3] = cpu_to_le32((h3 >> 18) | (h4 << 8));
}

/* Poly1305 benchmarking */

static void _poly1305(const struct poly1305_key *key, const void *src,
		      unsigned int srclen, u8 *digest, bool simd)
{
	struct poly1305_state state;
	le128 out;

	poly1305_init(&state);
	poly1305_tail(key, &state, src, srclen, simd);
	poly1305_emit(&state, &out, simd);
	memcpy(digest, &out, sizeof(out));
}

static void _poly1305_generic(const struct poly1305_key *key, const void *src,
			      unsigned int srclen, u8 *digest)
{
	_poly1305(key, src, srclen, digest, false);
}

#ifdef HAVE_POLY1305_SIMD
static void _poly1305_simd(const struct poly1305_key *key, const void *src,
			   unsigned int srclen, u8 *digest)
{
	_poly1305(key, src, srclen, digest, true);
}
#endif

void test_poly1305(void)
{
#define ALGNAME		"Poly1305"
#define HASH		_poly1305_generic
#ifdef HAVE_POLY1305_SIMD
#  define HASH_SIMD	_poly1305_simd
#endif
#define KEY		struct poly1305_key
#define SETKEY		poly1305_setkey
#define KEY_BYTES	POLY1305_BLOCK_SIZE
#define DIGEST_SIZE	POLY1305_DIGEST_SIZE
#include "hash_benchmark_template.h"
}
