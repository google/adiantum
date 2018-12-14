/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "util.h"

#define CHACHA_KEY_SIZE		32

/* 32-bit stream position, then 96-bit nonce (RFC7539 convention) */
#define CHACHA_IV_SIZE		16

/* 192-bit nonce, then 64-bit stream position */
#define XCHACHA_IV_SIZE		32

#define CHACHA_BLOCK_SIZE	64

struct chacha_ctx {
	u32 key[CHACHA_KEY_SIZE / 4];
	int nrounds;
};

void chacha_setkey(struct chacha_ctx *ctx, const u8 *key, int nrounds);

void chacha(const struct chacha_ctx *ctx, u8 *dst, const u8 *src,
	    unsigned int bytes, const u8 *iv, bool simd);
void xchacha(const struct chacha_ctx *ctx, u8 *dst, const u8 *src,
	     unsigned int nbytes, const u8 *iv, bool simd);

void chacha_init_state(u32 state[16], const struct chacha_ctx *ctx,
		       const u8 *iv);
void chacha_perm_generic(u32 x[16], int nrounds);
#ifdef __arm__
void chacha_perm_neon(u32 state[16], int nrounds);
#endif

#undef HAVE_CHACHA_SIMD
#undef HAVE_HCHACHA_SIMD

#if defined(__arm__) || defined(__aarch64__) || \
	(defined(__x86_64__) && defined(__SSSE3__))
#  define HAVE_CHACHA_SIMD 1
#  define HAVE_HCHACHA_SIMD 1
#endif
