/*
 * NEON-accelerated implementation of CHAM128-XTS
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
	ROUND_KEYS	.req	r0	// const u32 *round_keys
	NROUNDS		.req	r1	// int nrounds
	DST		.req	r2	// void *dst
	SRC		.req	r3	// const void *src
	NBYTES		.req	r4	// unsigned int nbytes
	TWEAK		.req	r5	// void *tweak

	ROUND_NUM	.req	r6

	// registers which hold the data being encrypted/decrypted
	X0_A		.req	q0
	X0_A_L		.req	d0
	X0_A_H		.req	d1
	X1_A		.req	q1
	X1_A_L		.req	d2
	X1_A_H		.req	d3
	X2_A		.req	q2
	X2_A_L		.req	d4
	X2_A_H		.req	d5
	X3_A		.req	q3
	X3_A_L		.req	d6
	X3_A_H		.req	d7
	X0_B		.req	q4
	X0_B_L		.req	d8
	X0_B_H		.req	d9
	X1_B		.req	q5
	X1_B_L		.req	d10
	X1_B_H		.req	d11
	X2_B		.req	q6
	X2_B_L		.req	d12
	X2_B_H		.req	d13
	X3_B		.req	q7
	X3_B_L		.req	d14
	X3_B_H		.req	d15

	// round key registers
	ROUND_KEY_A	.req	q8
	ROUND_KEY_A_L	.req	d16
	ROUND_KEY_A_H	.req	d17
	ROUND_KEY_B	.req	q9
	ROUND_KEY_B_L	.req	d18
	ROUND_KEY_B_H	.req	d19

	// current XTS tweak value(s)
	TWEAKV		.req	q10
	TWEAKV_L	.req	d20
	TWEAKV_H	.req	d21

	// index vector for vtbl-based 8-bit rotates
	ROL8_TABLE	.req	d22
	ROR8_TABLE	.req	d23

	TMP0_A		.req	q12
	TMP0_A_L	.req	d24
	TMP0_A_H	.req	d25
	TMP0_B		.req	q13
	TMP1_A		.req	q14
	TMP1_A_L	.req	d28
	TMP1_A_H	.req	d29
	TMP1_B		.req	q15
	TMP1_B_L	.req	d30
	TMP1_B_H	.req	d31

	// multiplication table for updating XTS tweaks
	GF128MUL_TABLE	.req	d31

.macro _cham_doubleround_128bytes	x0, x1, x2, x3, rk1, rk2

	// t1 = rol32((x0 ^ i) + (rol32(x1, 1) ^ ctx->round_keys[i & rk_mask]), 8);
	vdup.32		TMP0_A, ROUND_NUM
	add		ROUND_NUM, #1
	veor		\x0\()_A, TMP0_A
	veor		\x0\()_B, TMP0_A
	vdup.32		TMP0_A, \rk1
	vshl.u32	TMP1_A, \x1\()_A, #1
	vshl.u32	TMP1_B, \x1\()_B, #1
	vsri.u32	TMP1_A, \x1\()_A, #31
	vsri.u32	TMP1_B, \x1\()_B, #31
	veor		TMP1_A, TMP0_A
	veor		TMP1_B, TMP0_A
	vadd.u32	\x0\()_A, TMP1_A
	vadd.u32	\x0\()_B, TMP1_B
	vtbl.u8		\x0\()_A_L, {\x0\()_A_L}, ROL8_TABLE
	vtbl.u8		\x0\()_A_H, {\x0\()_A_H}, ROL8_TABLE
	vtbl.u8		\x0\()_B_L, {\x0\()_B_L}, ROL8_TABLE
	vtbl.u8		\x0\()_B_H, {\x0\()_B_H}, ROL8_TABLE

	// t2 = rol32((x1 ^ (i + 1)) + (rol32(x2, 8) ^ ctx->round_keys[(i + 1) & rk_mask]), 1);
	vdup.32		TMP0_A, ROUND_NUM
	add		ROUND_NUM, #1
	veor		\x1\()_A, TMP0_A
	veor		\x1\()_B, TMP0_A
	vdup.32		TMP0_A, \rk2
	vtbl.u8		TMP1_A_L, {\x2\()_A_L}, ROL8_TABLE
	vtbl.u8		TMP1_A_H, {\x2\()_A_H}, ROL8_TABLE
	vtbl.u8		TMP1_B_L, {\x2\()_B_L}, ROL8_TABLE
	vtbl.u8		TMP1_B_H, {\x2\()_B_H}, ROL8_TABLE
	veor		TMP1_A, TMP0_A
	veor		TMP1_B, TMP0_A
	vadd.u32	TMP1_A, \x1\()_A
	vadd.u32	TMP1_B, \x1\()_B
	vshl.u32	\x1\()_A, TMP1_A, #1
	vshl.u32	\x1\()_B, TMP1_B, #1
	vsri.u32	\x1\()_A, TMP1_A, #31
	vsri.u32	\x1\()_B, TMP1_B, #31

	// omitted, registers are relabeled instead
	// x0 = x2;
	// x1 = x3;
	// x2 = t1;
	// x3 = t2;
.endm

.macro _cham_doubleunround_128bytes	x0, x1, x2, x3, rk1, rk2

	// t1 = i ^ (ror32(x3, 1) - (rol32(x0, 8) ^ ctx->round_keys[i & rk_mask]));
	vdup.32		TMP0_A, \rk1
	vshr.u32	TMP1_A, \x3\()_A, #1
	vshr.u32	TMP1_B, \x3\()_B, #1
	vsli.u32	TMP1_A, \x3\()_A, #31
	vsli.u32	TMP1_B, \x3\()_B, #31
	vtbl.u8		\x3\()_A_L, {\x0\()_A_L}, ROL8_TABLE
	vtbl.u8		\x3\()_A_H, {\x0\()_A_H}, ROL8_TABLE
	vtbl.u8		\x3\()_B_L, {\x0\()_B_L}, ROL8_TABLE
	vtbl.u8		\x3\()_B_H, {\x0\()_B_H}, ROL8_TABLE
	veor		\x3\()_A, TMP0_A
	veor		\x3\()_B, TMP0_A
	vsub.u32	\x3\()_A, TMP1_A, \x3\()_A
	vsub.u32	\x3\()_B, TMP1_B, \x3\()_B
	vdup.32		TMP0_A, ROUND_NUM
	sub		ROUND_NUM, #1
	veor		\x3\()_A, TMP0_A
	veor		\x3\()_B, TMP0_A

	// t2 = (i - 1) ^ (ror32(x2, 8) - (rol32(t1, 1) ^ ctx->round_keys[(i - 1) & rk_mask]));
	vdup.32		TMP1_A, \rk2
	vshl.u32	TMP0_A, \x3\()_A, #1
	vshl.u32	TMP0_B, \x3\()_B, #1
	vsri.u32	TMP0_A, \x3\()_A, #31
	vsri.u32	TMP0_B, \x3\()_B, #31
	veor		TMP0_A, TMP1_A
	veor		TMP0_B, TMP1_A
	vtbl.u8		\x2\()_A_L, {\x2\()_A_L}, ROR8_TABLE
	vtbl.u8		\x2\()_A_H, {\x2\()_A_H}, ROR8_TABLE
	vtbl.u8		\x2\()_B_L, {\x2\()_B_L}, ROR8_TABLE
	vtbl.u8		\x2\()_B_H, {\x2\()_B_H}, ROR8_TABLE
	vsub.u32	\x2\()_A, TMP0_A
	vsub.u32	\x2\()_B, TMP0_B
	vdup.32		TMP0_A, ROUND_NUM
	sub		ROUND_NUM, #1
	veor		\x2\()_A, TMP0_A
	veor		\x2\()_B, TMP0_A

	// omitted, registers are relabeled instead
	// x3 = x1;
	// x2 = x0;
	// x1 = t1;
	// x0 = t2;
.endm

.macro _xts128_precrypt_one	dst_reg, tweak_buf, tmp

	// Load the next source block
	vld1.8		{\dst_reg}, [SRC]!

	// Save the current tweak in the tweak buffer
	vst1.8		{TWEAKV}, [\tweak_buf:128]!

	// XOR the next source block with the current tweak
	veor		\dst_reg, TWEAKV

	/*
	 * Calculate the next tweak by multiplying the current one by x,
	 * modulo p(x) = x^128 + x^7 + x^2 + x + 1.
	 */
	vshr.u64	\tmp, TWEAKV, #63
	vshl.u64	TWEAKV, #1
	veor		TWEAKV_H, \tmp\()_L
	vtbl.8		\tmp\()_H, {GF128MUL_TABLE}, \tmp\()_H
	veor		TWEAKV_L, \tmp\()_H
.endm

.macro _cham_xts_crypt	decrypting
	push		{r4-r7}

	/*
	 * The first four parameters were passed in registers r0-r3.  Load the
	 * additional parameters, which were passed on the stack.
	 */
	ldr		NBYTES, [sp, #16]
	ldr		TWEAK, [sp, #20]

	// Save the callee-saved NEON registers.
	vstmdb		sp!, {q4-q7}

	mov		r7, sp

	// Load the round keys
	vld1.8		{ROUND_KEY_A, ROUND_KEY_B}, [ROUND_KEYS]

	// Load the index vectors for vtbl-based 8-bit rotates
	b 1f
	.align 3
.Lror32_8_table_\@:
	.byte		1, 2, 3, 0, 5, 6, 7, 4
.Lrol32_8_table_\@:
	.byte		3, 0, 1, 2, 7, 4, 5, 6
1:
	adr		r12, .Lrol32_8_table_\@
	vld1.8		{ROL8_TABLE}, [r12:64]
	adr		r12, .Lror32_8_table_\@
	vld1.8		{ROR8_TABLE}, [r12:64]

	// One-time XTS preparation

	/*
	 * Allocate stack space to store 128 bytes worth of tweaks.  For
	 * performance, this space is aligned to a 16-byte boundary so that we
	 * can use the load/store instructions that declare 16-byte alignment.
	 */
	sub		sp, #128
	bic		sp, #0xf

	// Load first tweak
	vld1.8		{TWEAKV}, [TWEAK]

.Lnext_128bytes_\@:

	// Load GF(2^128) multiplication table
	b 1f
	.align 4
.Lgf128mul_table_\@:
	.byte		0, 0x87
	.fill		14
1:
	adr		r12, .Lgf128mul_table_\@
	vld1.8		{GF128MUL_TABLE}, [r12:64]

	/*
	 * Load the source blocks into q0-q7, XOR them with their XTS tweak
	 * values, and save the tweaks on the stack for later.
	 */
	mov		r12, sp
	_xts128_precrypt_one	q0, r12, TMP0_A
	_xts128_precrypt_one	q1, r12, TMP0_A
	_xts128_precrypt_one	q2, r12, TMP0_A
	_xts128_precrypt_one	q3, r12, TMP0_A
	_xts128_precrypt_one	q4, r12, TMP0_A
	_xts128_precrypt_one	q5, r12, TMP0_A
	_xts128_precrypt_one	q6, r12, TMP0_A
	_xts128_precrypt_one	q7, r12, TMP0_A

	// Store the next tweak
	vst1.8		{TWEAKV}, [TWEAK]

	/*
	 * De-interleave the 32-bit words (x0, x1, x2, x3) of the blocks such
	 * that X0_{A,B} contain all x0, X1_{A,B} contain all x1, and so on.
	 */
	vuzp.32		q0, q1	// => (x0, x2, x0, x2) and (x1, x3, x1, x3)
	vuzp.32		q2, q3	// => (x0, x2, x0, x2) and (x1, x3, x1, x3)
	vuzp.32		q4, q5	// => (x0, x2, x0, x2) and (x1, x3, x1, x3)
	vuzp.32		q6, q7	// => (x0, x2, x0, x2) and (x1, x3, x1, x3)
	vuzp.32		q0, q2	// => (x0, x0, x0, x0) and (x2, x2, x2, x2)
	vuzp.32		q1, q3	// => (x1, x1, x1, x1) and (x3, x3, x3, x3)
	vuzp.32		q4, q6	// => (x0, x0, x0, x0) and (x2, x2, x2, x2)
	vuzp.32		q5, q7	// => (x1, x1, x1, x1) and (x3, x3, x3, x3)

	// Do the cipher rounds
.if \decrypting
	sub		ROUND_NUM, NROUNDS, #1
.else
	mov		ROUND_NUM, #0
.endif

.Lnext_round_\@:
.if \decrypting
	_cham_doubleunround_128bytes	X0, X1, X2, X3, ROUND_KEY_B_H[1], ROUND_KEY_B_H[0]
	_cham_doubleunround_128bytes	X2, X3, X0, X1, ROUND_KEY_B_L[1], ROUND_KEY_B_L[0]
	_cham_doubleunround_128bytes	X0, X1, X2, X3, ROUND_KEY_A_H[1], ROUND_KEY_A_H[0]
	_cham_doubleunround_128bytes	X2, X3, X0, X1, ROUND_KEY_A_L[1], ROUND_KEY_A_L[0]
	cmp		ROUND_NUM, #0
	bge		.Lnext_round_\@
.else
	_cham_doubleround_128bytes	X0, X1, X2, X3, ROUND_KEY_A_L[0], ROUND_KEY_A_L[1]
	_cham_doubleround_128bytes	X2, X3, X0, X1, ROUND_KEY_A_H[0], ROUND_KEY_A_H[1]
	_cham_doubleround_128bytes	X0, X1, X2, X3, ROUND_KEY_B_L[0], ROUND_KEY_B_L[1]
	_cham_doubleround_128bytes	X2, X3, X0, X1, ROUND_KEY_B_H[0], ROUND_KEY_B_H[1]
	cmp		ROUND_NUM, NROUNDS
	bne		.Lnext_round_\@
.endif

	// Re-interleave the 32-bit words (x0, x1, x2, x3) of the blocks
	vzip.32		q0, q2
	vzip.32		q1, q3
	vzip.32		q4, q6
	vzip.32		q5, q7
	vzip.32		q0, q1
	vzip.32		q2, q3
	vzip.32		q4, q5
	vzip.32		q6, q7

	// XOR the encrypted/decrypted blocks with the tweaks we saved earlier
	mov		r12, sp
	vld1.8		{TMP0_A, TMP0_B}, [r12:128]!
	vld1.8		{TMP1_A, TMP1_B}, [r12:128]!
	veor		q0, TMP0_A
	veor		q1, TMP0_B
	veor		q2, TMP1_A
	veor		q3, TMP1_B
	vld1.8		{TMP0_A, TMP0_B}, [r12:128]!
	vld1.8		{TMP1_A, TMP1_B}, [r12:128]!
	veor		q4, TMP0_A
	veor		q5, TMP0_B
	veor		q6, TMP1_A
	veor		q7, TMP1_B

	// Store the ciphertext in the destination buffer
	vst1.8		{q0, q1}, [DST]!
	vst1.8		{q2, q3}, [DST]!
	vst1.8		{q4, q5}, [DST]!
	vst1.8		{q6, q7}, [DST]!

	// Continue if there are more 128-byte chunks remaining, else return
	subs		NBYTES, #128
	bne		.Lnext_128bytes_\@

	// Store the next tweak
	vst1.8		{TWEAKV}, [TWEAK]

	mov		sp, r7
	vldmia		sp!, {q4-q7}
	pop		{r4-r7}
	bx		lr
.endm

ENTRY(cham128_xts_encrypt_neon)
	_cham_xts_crypt	decrypting=0
ENDPROC(cham128_xts_encrypt_neon)

ENTRY(cham128_xts_decrypt_neon)
	_cham_xts_crypt	decrypting=1
ENDPROC(cham128_xts_decrypt_neon)
