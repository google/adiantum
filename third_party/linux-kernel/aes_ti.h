/*
 * Scalar fixed time AES core transform
 *
 * Copyright (C) 2017 Linaro Ltd <ard.biesheuvel@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#pragma once

#include "util.h"

#define AES_MIN_KEY_SIZE	16
#define AES_MAX_KEY_SIZE	32
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32
#define AES_BLOCK_SIZE		16
#define AES_MAX_KEYLENGTH	(15 * 16)
#define AES_MAX_KEYLENGTH_U32	(AES_MAX_KEYLENGTH / sizeof(u32))

/*
 * Please ensure that the first two fields are 16-byte aligned
 * relative to the start of the structure, i.e., don't move them!
 */
struct crypto_aes_ctx {
	u32 key_enc[AES_MAX_KEYLENGTH_U32];
	u32 key_dec[AES_MAX_KEYLENGTH_U32];
	u32 key_length;
};

int aesti_set_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
			 unsigned int key_len);
void aesti_encrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);
void aesti_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);

/* WARNING: this does not create keys that are usable in aesti_*
   but they are used to set up NEON encryption. */
int aesti_expand_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
			    unsigned int key_len);
