/*
 * NEON-accelerated implementation of XTEA-XTS
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * Author: Eric Biggers <ebiggers@google.com>
 */

#include "../asm_common.h"

	.text
	.fpu		neon

	// arguments
	KEY		.req	r0	// const u32 *key
	DST		.req	r1	// void *dst
	SRC		.req	r2	// const void *src
	NBYTES		.req	r3	// unsigned int nbytes
	TWEAK		.req	r4	// void *tweak

	// registers which hold the data being encrypted/decrypted
	Y0		.req	q0
	Y0_L		.req	d0
	Y0_H		.req	d1
	Z0		.req	q1
	Z0_H		.req	d3
	Y1		.req	q2
	Y1_L		.req	d4
	Y1_H		.req	d5
	Z1		.req	q3
	Z1_H		.req	d7
	Y2		.req	q4
	Y2_L		.req	d8
	Y2_H		.req	d9
	Z2		.req	q5
	Z2_H		.req	d11
	Y3		.req	q6
	Y3_L		.req	d12
	Y3_H		.req	d13
	Z3		.req	q7
	Z3_H		.req	d15

	// key register
	KEYV		.req	q8
	KEYV_L		.req	d16
	KEYV_H		.req	d17

	SUM		.req	q9
	DELTA		.req	q10

	KEYTMP		.req	q11

	TMP0		.req	q12
	TMP0_L		.req	d24
	TMP0_H		.req	d25
	TMP1		.req	q13
	TMP2		.req	q14
	TMP3		.req	q15

	// multiplication table for updating XTS tweaks
	GF64MUL_TABLE	.req	d28

	// current XTS tweak value(s)
	TWEAKV		.req	q15
	TWEAKV_L	.req	d30
	TWEAKV_H	.req	d31


	// a OP= ((b << 4 ^ b >> 5) + b) ^ (sum + k)
.macro _xtea_do_round_128bytes	A, B, op, k
	vdup.u32	KEYTMP, \k
	vshl.u32	TMP0, \B\()0, #4
	vshl.u32	TMP1, \B\()1, #4
	vshr.u32	TMP2, \B\()0, #5
	vshr.u32	TMP3, \B\()1, #5
	veor		TMP0, TMP2
	veor		TMP1, TMP3
	vadd.u32	KEYTMP, SUM
	vadd.u32	TMP0, \B\()0
	vadd.u32	TMP1, \B\()1
	vshr.u32	TMP2, \B\()2, #5
	vshr.u32	TMP3, \B\()3, #5
	veor		TMP0, KEYTMP
	veor		TMP1, KEYTMP
	v\op\().u32	\A\()0, TMP0
	v\op\().u32	\A\()1, TMP1
	vshl.u32	TMP0, \B\()2, #4
	vshl.u32	TMP1, \B\()3, #4
	veor		TMP0, TMP2
	veor		TMP1, TMP3
	vadd.u32	TMP0, \B\()2
	vadd.u32	TMP1, \B\()3
	veor		TMP0, KEYTMP
	veor		TMP1, KEYTMP
	v\op\().u32	\A\()2, TMP0
	v\op\().u32	\A\()3, TMP1
.endm

.macro _xtea_do_doubleround_128bytes	A, B, op, k1, k2
	_xtea_do_round_128bytes	\A, \B, \op, \k1
	v\op\().u32		SUM, DELTA
	_xtea_do_round_128bytes	\B, \A, \op, \k2
.endm

.macro _xtea_doubleround_128bytes	k1, k2
	_xtea_do_doubleround_128bytes	Y, Z, add, \k1, \k2
.endm

.macro _xtea_doubleunround_128bytes	k1, k2
	_xtea_do_doubleround_128bytes	Z, Y, sub, \k2, \k1
.endm

.macro _xts64_precrypt_two	dst_reg, tweak_buf, tmp

	// Load the next two source blocks
	vld1.8		{\dst_reg}, [SRC]!

	// Save the current two tweaks in the tweak buffer
	vst1.8		{TWEAKV}, [\tweak_buf:128]!

	// XOR the next two source blocks with the current two tweaks
	veor		\dst_reg, TWEAKV

	/*
	 * Calculate the next two tweaks by multiplying the current ones by x^2,
	 * modulo p(x) = x^64 + x^4 + x^3 + x + 1.
	 */
	vshr.u64	\tmp, TWEAKV, #62
	vshl.u64	TWEAKV, #2
	vtbl.8		\tmp\()_L, {GF64MUL_TABLE}, \tmp\()_L
	vtbl.8		\tmp\()_H, {GF64MUL_TABLE}, \tmp\()_H
	veor		TWEAKV, \tmp
.endm

.macro _xtea_xts_crypt	decrypting
	push		{r4-r5}
	mov		r5, sp

	/*
	 * The first four parameters were passed in registers r0-r3.  Load the
	 * additional parameter, which was passed on the stack.
	 */
	ldr		TWEAK, [sp, #8]

	// Load the key
	vld1.8		{KEYV}, [KEY]

	// Load the XTEA_DELTA constants
	b 1f
	.align 4
.Ldeltas\@:
	.word		0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9
1:
	adr		r12, .Ldeltas\@
	vld1.8		{DELTA}, [r12:128]

	/*
	 * Allocate stack space to store 128 bytes worth of tweaks.  For
	 * performance, this space is aligned to a 16-byte boundary so that we
	 * can use the load/store instructions that declare 16-byte alignment.
	 */
	sub		sp, #128
	bic		sp, #0xf

.Lnext_128bytes_\@:

	// Load first tweak
	vld1.8		{TWEAKV_L}, [TWEAK]

	// Load GF(2^64) multiplication table
	b 1f
	.align 4
.Lgf64mul_table_\@:
	.byte		0, 0x1b, (0x1b << 1), (0x1b << 1) ^ 0x1b
	.fill		12
1:
	adr		r12, .Lgf64mul_table_\@
	vld1.8		{GF64MUL_TABLE}, [r12:64]

	// Calculate second tweak, packing it together with the first
	vshr.u64	TMP0_L, TWEAKV_L, #63
	vtbl.u8		TMP0_L, {GF64MUL_TABLE}, TMP0_L
	vshl.u64	TWEAKV_H, TWEAKV_L, #1
	veor		TWEAKV_H, TMP0_L

	/*
	 * Load the source blocks into {Y,Z}[0-3], XOR them with their XTS tweak
	 * values, and save the tweaks on the stack for later.  Then
	 * de-interleave the 'y' and 'z' elements of each block, i.e. make it so
	 * that the X[0-3] registers contain only the first halves of blocks,
	 * and the Y[0-3] registers contain only the second halves of blocks.
	 */
	mov		r12, sp
	_xts64_precrypt_two	Y0, r12, TMP0
	_xts64_precrypt_two	Z0, r12, TMP0
	_xts64_precrypt_two	Y1, r12, TMP0
	_xts64_precrypt_two	Z1, r12, TMP0
	_xts64_precrypt_two	Y2, r12, TMP0
	_xts64_precrypt_two	Z2, r12, TMP0
	_xts64_precrypt_two	Y3, r12, TMP0
	_xts64_precrypt_two	Z3, r12, TMP0

	// Store the next tweak
	vst1.8		{TWEAKV_L}, [TWEAK]

	vuzp.32		Y0, Z0
	vuzp.32		Y1, Z1
	vuzp.32		Y2, Z2
	vuzp.32		Y3, Z3

	// Do the cipher rounds

.if \decrypting
	// Load XTEA_DELTA * XTEA_ROUNDS
	b 1f
	.align 4
.Lfinal_sums\@:
	.word		0xc6ef3720, 0xc6ef3720, 0xc6ef3720, 0xc6ef3720
1:
	adr		r12, .Lfinal_sums\@
	vld1.8		{SUM}, [r12:128]

	_xtea_doubleunround_128bytes KEYV_H[1], KEYV_H[0]
	_xtea_doubleunround_128bytes KEYV_H[0], KEYV_H[1]
	_xtea_doubleunround_128bytes KEYV_L[1], KEYV_L[0]
	_xtea_doubleunround_128bytes KEYV_L[0], KEYV_L[1]
	_xtea_doubleunround_128bytes KEYV_H[1], KEYV_H[0]
	_xtea_doubleunround_128bytes KEYV_H[0], KEYV_H[0]
	_xtea_doubleunround_128bytes KEYV_L[1], KEYV_H[1]
	_xtea_doubleunround_128bytes KEYV_L[0], KEYV_L[0]
	_xtea_doubleunround_128bytes KEYV_H[1], KEYV_L[1]
	_xtea_doubleunround_128bytes KEYV_H[0], KEYV_L[1]
	_xtea_doubleunround_128bytes KEYV_L[1], KEYV_H[0]
	_xtea_doubleunround_128bytes KEYV_L[0], KEYV_H[1]
	_xtea_doubleunround_128bytes KEYV_H[1], KEYV_L[0]
	_xtea_doubleunround_128bytes KEYV_H[0], KEYV_L[1]
	_xtea_doubleunround_128bytes KEYV_L[1], KEYV_L[1]
	_xtea_doubleunround_128bytes KEYV_L[0], KEYV_H[0]
	_xtea_doubleunround_128bytes KEYV_H[1], KEYV_H[1]
	_xtea_doubleunround_128bytes KEYV_H[0], KEYV_L[0]
	_xtea_doubleunround_128bytes KEYV_L[1], KEYV_L[1]
	_xtea_doubleunround_128bytes KEYV_L[0], KEYV_L[1]
	_xtea_doubleunround_128bytes KEYV_H[1], KEYV_H[0]
	_xtea_doubleunround_128bytes KEYV_H[0], KEYV_H[1]
	_xtea_doubleunround_128bytes KEYV_L[1], KEYV_L[0]
	_xtea_doubleunround_128bytes KEYV_L[0], KEYV_L[0]
	_xtea_doubleunround_128bytes KEYV_H[1], KEYV_L[1]
	_xtea_doubleunround_128bytes KEYV_H[0], KEYV_H[0]
	_xtea_doubleunround_128bytes KEYV_L[1], KEYV_H[1]
	_xtea_doubleunround_128bytes KEYV_L[0], KEYV_L[0]
	_xtea_doubleunround_128bytes KEYV_H[1], KEYV_L[0]
	_xtea_doubleunround_128bytes KEYV_H[0], KEYV_L[1]
	_xtea_doubleunround_128bytes KEYV_L[1], KEYV_H[0]
	_xtea_doubleunround_128bytes KEYV_L[0], KEYV_H[1]
.else
	veor		SUM, SUM
	_xtea_doubleround_128bytes KEYV_L[0], KEYV_H[1]
	_xtea_doubleround_128bytes KEYV_L[1], KEYV_H[0]
	_xtea_doubleround_128bytes KEYV_H[0], KEYV_L[1]
	_xtea_doubleround_128bytes KEYV_H[1], KEYV_L[0]
	_xtea_doubleround_128bytes KEYV_L[0], KEYV_L[0]
	_xtea_doubleround_128bytes KEYV_L[1], KEYV_H[1]
	_xtea_doubleround_128bytes KEYV_H[0], KEYV_H[0]
	_xtea_doubleround_128bytes KEYV_H[1], KEYV_L[1]
	_xtea_doubleround_128bytes KEYV_L[0], KEYV_L[0]
	_xtea_doubleround_128bytes KEYV_L[1], KEYV_L[0]
	_xtea_doubleround_128bytes KEYV_H[0], KEYV_H[1]
	_xtea_doubleround_128bytes KEYV_H[1], KEYV_H[0]
	_xtea_doubleround_128bytes KEYV_L[0], KEYV_L[1]
	_xtea_doubleround_128bytes KEYV_L[1], KEYV_L[1]
	_xtea_doubleround_128bytes KEYV_H[0], KEYV_L[0]
	_xtea_doubleround_128bytes KEYV_H[1], KEYV_H[1]
	_xtea_doubleround_128bytes KEYV_L[0], KEYV_H[0]
	_xtea_doubleround_128bytes KEYV_L[1], KEYV_L[1]
	_xtea_doubleround_128bytes KEYV_H[0], KEYV_L[1]
	_xtea_doubleround_128bytes KEYV_H[1], KEYV_L[0]
	_xtea_doubleround_128bytes KEYV_L[0], KEYV_H[1]
	_xtea_doubleround_128bytes KEYV_L[1], KEYV_H[0]
	_xtea_doubleround_128bytes KEYV_H[0], KEYV_L[1]
	_xtea_doubleround_128bytes KEYV_H[1], KEYV_L[1]
	_xtea_doubleround_128bytes KEYV_L[0], KEYV_L[0]
	_xtea_doubleround_128bytes KEYV_L[1], KEYV_H[1]
	_xtea_doubleround_128bytes KEYV_H[0], KEYV_H[0]
	_xtea_doubleround_128bytes KEYV_H[1], KEYV_H[0]
	_xtea_doubleround_128bytes KEYV_L[0], KEYV_L[1]
	_xtea_doubleround_128bytes KEYV_L[1], KEYV_L[0]
	_xtea_doubleround_128bytes KEYV_H[0], KEYV_H[1]
	_xtea_doubleround_128bytes KEYV_H[1], KEYV_H[0]
.endif

	// Re-interleave the 'x' and 'y' elements of each block
	vzip.32		Y0, Z0
	vzip.32		Y1, Z1
	vzip.32		Y2, Z2
	vzip.32		Y3, Z3

	// XOR the encrypted/decrypted blocks with the tweaks we saved earlier
	mov		r12, sp
	vld1.8		{TMP0, TMP1}, [r12:128]!
	vld1.8		{TMP2, TMP3}, [r12:128]!
	veor		Y0, TMP0
	veor		Z0, TMP1
	veor		Y1, TMP2
	veor		Z1, TMP3
	vld1.8		{TMP0, TMP1}, [r12:128]!
	vld1.8		{TMP2, TMP3}, [r12:128]!
	veor		Y2, TMP0
	veor		Z2, TMP1
	veor		Y3, TMP2
	veor		Z3, TMP3

	// Store the ciphertext in the destination buffer
	vst1.8		{Y0, Z0}, [DST]!
	vst1.8		{Y1, Z1}, [DST]!
	vst1.8		{Y2, Z2}, [DST]!
	vst1.8		{Y3, Z3}, [DST]!

	// Continue if there are more 128-byte chunks remaining, else return
	subs		NBYTES, #128
	bne		.Lnext_128bytes_\@

	mov		sp, r5
	pop		{r4-r5}
	bx		lr
.endm

ENTRY(xtea_xts_encrypt_neon)
	_xtea_xts_crypt	decrypting=0
ENDPROC(xtea_xts_encrypt_neon)

ENTRY(xtea_xts_decrypt_neon)
	_xtea_xts_crypt	decrypting=1
ENDPROC(xtea_xts_decrypt_neon)
