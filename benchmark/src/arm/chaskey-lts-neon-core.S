/*
 * NEON-accelerated implementation of Chaskey-LTS-XTS
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
	KEY		.req	r0	// const u32 key[]
	DST		.req	r1	// void *dst
	SRC		.req	r2	// const void *src
	NBYTES		.req	r3	// unsigned int nbytes
	TWEAK		.req	r4	// void *tweak

	// registers which hold the data being encrypted/decrypted
	V0_A		.req	q0
	V2_A		.req	q1
	V1_A		.req	q2
	V3_A		.req	q3
	V3_AL		.req	d6
	V3_AH		.req	d7
	V0_B		.req	q4
	V2_B		.req	q5
	V1_B		.req	q6
	V3_B		.req	q7
	V3_BL		.req	d14
	V3_BH		.req	d15

	// the key
	KEYV		.req	q8

	// index vector for vtbl-based 8-bit rotates
	ROTATE8_TABLE	.req	d18

	// multiplication table for updating XTS tweaks
	GF128MUL_TABLE	.req	d19

	// current XTS tweak value
	TWEAKV		.req	q10
	TWEAKV_L	.req	d20
	TWEAKV_H	.req	d21

	TMP0		.req	q11
	TMP0_L		.req	d22
	TMP0_H		.req	d23
	TMP1		.req	q12
	TMP2		.req	q13
	TMP3		.req	q14

.macro _chaskey_round_128bytes

	// v0 += v1
	vadd.u32	V0_A, V1_A
	vadd.u32	V0_B, V1_B

	// v1 = rol32(v1, 5)
	vshl.u32	TMP0, V1_A, #5
	vshl.u32	TMP1, V1_B, #5
	vsri.u32	TMP0, V1_A, #(32 - 5)
	vsri.u32	TMP1, V1_B, #(32 - 5)

	// v1 ^= v0
	veor		V1_A, TMP0, V0_A
	veor		V1_B, TMP1, V0_B

	// v0 = rol32(v0, 16)
	vrev32.16	V0_A, V0_A
	vrev32.16	V0_B, V0_B

	// v2 += v3
	vadd.u32	V2_A, V3_A
	vadd.u32	V2_B, V3_B

	// v3 = rol32(v3, 8)
	vtbl.8		V3_AL, {V3_AL}, ROTATE8_TABLE
	vtbl.8		V3_AH, {V3_AH}, ROTATE8_TABLE
	vtbl.8		V3_BL, {V3_BL}, ROTATE8_TABLE
	vtbl.8		V3_BH, {V3_BH}, ROTATE8_TABLE

	// v3 ^= v2
	veor		V3_A, V2_A
	veor		V3_B, V2_B

	// v0 += v3
	vadd.u32	V0_A, V3_A
	vadd.u32	V0_B, V3_B

	// v3 = rol32(v3, 13)
	vshl.u32	TMP0, V3_A, #13
	vshl.u32	TMP1, V3_B, #13
	vsri.u32	TMP0, V3_A, #(32 - 13)
	vsri.u32	TMP1, V3_B, #(32 - 13)

	// v3 ^= v0
	veor		V3_A, TMP0, V0_A
	veor		V3_B, TMP1, V0_B

	// v2 += v1
	vadd.u32	V2_A, V1_A
	vadd.u32	V2_B, V1_B

	// v1 = rol32(v1, 7)
	vshl.u32	TMP0, V1_A, #7
	vshl.u32	TMP1, V1_B, #7
	vsri.u32	TMP0, V1_A, #(32 - 7)
	vsri.u32	TMP1, V1_B, #(32 - 7)

	// v1 ^= v2
	veor		V1_A, TMP0, V2_A
	veor		V1_B, TMP1, V2_B

	// v2 = rol32(v2, 16)
	vrev32.16	V2_A, V2_A
	vrev32.16	V2_B, V2_B
.endm

.macro _chaskey_unround_128bytes

	// v2 = ror32(v2, 16)
	vrev32.16	V2_A, V2_A
	vrev32.16	V2_B, V2_B

	// v1 ^= v2
	veor		V1_A, V2_A
	veor		V1_B, V2_B

	// v1 = ror32(v1, 7)
	vshr.u32	TMP0, V1_A, #7
	vshr.u32	TMP1, V1_B, #7
	vsli.u32	TMP0, V1_A, #(32 - 7)
	vsli.u32	TMP1, V1_B, #(32 - 7)

	// v2 -= v1
	vsub.u32	V2_A, TMP0
	vsub.u32	V2_B, TMP1

	// v3 ^= v0
	veor		V3_A, V0_A
	veor		V3_B, V0_B

	// v3 = ror32(v3, 13)
	vshr.u32	TMP2, V3_A, #13
	vshr.u32	TMP3, V3_B, #13
	vsli.u32	TMP2, V3_A, #(32 - 13)
	vsli.u32	TMP3, V3_B, #(32 - 13)

	// v0 -= v3
	vsub.u32	V0_A, TMP2
	vsub.u32	V0_B, TMP3

	// v3 ^= v2
	veor		V3_A, TMP2, V2_A
	veor		V3_B, TMP3, V2_B

	// v3 = ror32(v3, 8)
	vtbl.8		V3_AL, {V3_AL}, ROTATE8_TABLE
	vtbl.8		V3_AH, {V3_AH}, ROTATE8_TABLE
	vtbl.8		V3_BL, {V3_BL}, ROTATE8_TABLE
	vtbl.8		V3_BH, {V3_BH}, ROTATE8_TABLE

	// v2 -= v3
	vsub.u32	V2_A, V3_A
	vsub.u32	V2_B, V3_B

	// v0 = ror32(v0, 16)
	vrev32.16	V0_A, V0_A
	vrev32.16	V0_B, V0_B

	// v1 ^= v0
	veor		TMP0, TMP0, V0_A
	veor		TMP1, TMP1, V0_B

	// v1 = ror32(v1, 5)
	vshr.u32	V1_A, TMP0, #5
	vshr.u32	V1_B, TMP1, #5
	vsli.u32	V1_A, TMP0, #(32 - 5)
	vsli.u32	V1_B, TMP1, #(32 - 5)

	// v0 -= v1
	vsub.u32	V0_A, V1_A
	vsub.u32	V0_B, V1_B
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

.macro _chaskey_lts_xts_crypt	decrypting
	push		{r4-r5}
	mov		r5, sp

	/*
	 * The first four parameters were passed in registers r0-r3.  Load the
	 * additional parameter, which was passed on the stack.
	 */
	ldr		TWEAK, [sp, #8]

	// Load key
	vld1.8		{KEYV}, [KEY]

	// Load the index vectors for vtbl-based 8-bit rotates
	b 1f
	.align 3
.if \decrypting
.Lror32_8_table:
	.byte		1, 2, 3, 0, 5, 6, 7, 4
1:
	adr		r12, .Lror32_8_table
.else
.Lrol32_8_table:
	.byte		3, 0, 1, 2, 7, 4, 5, 6
1:
	adr		r12, .Lrol32_8_table
.endif
	vld1.8		{ROTATE8_TABLE}, [r12:64]

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

	// Load GF(2^128) multiplication table
	b 1f
	.align 4
.Lgf128mul_table_\@:
	.byte		0, 0x87
	.fill		14
1:
	adr		r12, .Lgf128mul_table_\@
	vld1.8		{GF128MUL_TABLE}, [r12:64]

.Lnext_128bytes_\@:

	mov		r12, sp

	_xts128_precrypt_one	q0, r12, TMP0
	_xts128_precrypt_one	q1, r12, TMP0
	_xts128_precrypt_one	q2, r12, TMP0
	_xts128_precrypt_one	q3, r12, TMP0
	_xts128_precrypt_one	q4, r12, TMP0
	_xts128_precrypt_one	q5, r12, TMP0
	_xts128_precrypt_one	q6, r12, TMP0
	_xts128_precrypt_one	q7, r12, TMP0

	// Pre-whiten (XOR with key)
	veor		q0, KEYV
	veor		q1, KEYV
	veor		q2, KEYV
	veor		q3, KEYV
	veor		q4, KEYV
	veor		q5, KEYV
	veor		q6, KEYV
	veor		q7, KEYV

	// De-interleave the (v0, v1, v2, v3)
	vzip.32		q0, q1
	vzip.32		q2, q3
	vzip.32		q4, q5
	vzip.32		q6, q7
	vswp		d1, d4		// V0_A, V1_A
	vswp		d3, d6		// V2_A, V3_A
	vswp		d9, d12		// V0_B, V1_B
	vswp		d11, d14	// V2_B, V3_B

	// Do the cipher rounds
	mov		r12, #16		// number of rounds
.Lnext_round_\@:
.if \decrypting
	_chaskey_unround_128bytes
.else
	_chaskey_round_128bytes
.endif
	subs		r12, r12, #1
	bne		.Lnext_round_\@

	// Re-interleave the (v0, v1, v2, v3)
	vswp		d1, d4		// V0_A, V1_A
	vswp		d3, d6		// V2_A, V3_A
	vswp		d9, d12		// V0_B, V1_B
	vswp		d11, d14	// V2_B, V3_B
	vuzp.32		q0, q1
	vuzp.32		q2, q3
	vuzp.32		q4, q5
	vuzp.32		q6, q7

	// Post-whiten (XOR with key)
	veor		q0, KEYV
	veor		q1, KEYV
	veor		q2, KEYV
	veor		q3, KEYV
	veor		q4, KEYV
	veor		q5, KEYV
	veor		q6, KEYV
	veor		q7, KEYV

	// XOR the encrypted/decrypted blocks with the tweaks we saved earlier
	mov		r12, sp
	vld1.8		{TMP0, TMP1}, [r12:128]!
	vld1.8		{TMP2, TMP3}, [r12:128]!
	veor		q0, TMP0
	veor		q1, TMP1
	veor		q2, TMP2
	veor		q3, TMP3
	vld1.8		{TMP0, TMP1}, [r12:128]!
	vld1.8		{TMP2, TMP3}, [r12:128]!
	veor		q4, TMP0
	veor		q5, TMP1
	veor		q6, TMP2
	veor		q7, TMP3

	// Store the ciphertext in the destination buffer
	vst1.8		{q0-q1}, [DST]!
	vst1.8		{q2-q3}, [DST]!
	vst1.8		{q4-q5}, [DST]!
	vst1.8		{q6-q7}, [DST]!

	// Continue if there are more 128-byte chunks remaining, else return
	subs		NBYTES, #128
	bne		.Lnext_128bytes_\@

	// Store the next tweak
	vst1.8		{TWEAKV}, [TWEAK]

	mov		sp, r5
	pop		{r4-r5}
	bx		lr
.endm

ENTRY(chaskey_lts_xts_encrypt_neon)
	_chaskey_lts_xts_crypt	decrypting=0
ENDPROC(chaskey_lts_xts_encrypt_neon)

ENTRY(chaskey_lts_xts_decrypt_neon)
	_chaskey_lts_xts_crypt	decrypting=1
ENDPROC(chaskey_lts_xts_decrypt_neon)
