/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "util.h"

struct noekeon_ctx {
	u32 enckey[4];
	u32 deckey[4];
};

void noekeon_encrypt(const struct noekeon_ctx *ctx, u8 *dst, const u8 *src);
void noekeon_decrypt(const struct noekeon_ctx *ctx, u8 *dst, const u8 *src);
void noekeon_setkey(struct noekeon_ctx *ctx, const u8 *key);
