/*
 * NEON-accelerated implementation of RC5-128-XTS and RC5-64-XTS
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
	ROUND_KEYS	.req	r0	// const {u64,u32} *round_keys
	NROUNDS		.req	r1	// int nrounds
	DST		.req	r2	// void *dst
	SRC		.req	r3	// const void *src
	NBYTES		.req	r4	// unsigned int nbytes
	TWEAK		.req	r5	// void *tweak

	CONST_N_MINUS_1	.req	r6
	CONST_N		.req	r7

	// registers which hold the data being encrypted/decrypted
	A_0		.req	q0
	A_0_L		.req	d0
	A_0_H		.req	d1
	B_0		.req	q1
	B_0_L		.req	d2
	A_1		.req	q2
	A_1_L		.req	d4
	A_1_H		.req	d5
	B_1		.req	q3
	B_1_L		.req	d6
	A_2		.req	q4
	A_2_L		.req	d8
	A_2_H		.req	d9
	B_2		.req	q5
	B_2_L		.req	d10
	A_3		.req	q6
	A_3_L		.req	d12
	A_3_H		.req	d13
	B_3		.req	q7
	B_3_L		.req	d14

	// the round key, duplicated in all lanes
	ROUND_KEY_0	.req	q8
	ROUND_KEY_0_L	.req	d16
	ROUND_KEY_0_H	.req	d17

	ROUND_KEY_1	.req	q9
	ROUND_KEY_1_L	.req	d18
	ROUND_KEY_1_H	.req	d19

	// current XTS tweak value(s)
	TWEAKV		.req	q10
	TWEAKV_L	.req	d20
	TWEAKV_H	.req	d21

	// multiplication table for updating XTS tweaks
	GF128MUL_TABLE	.req	d22
	GF64MUL_TABLE	.req	d22

	TMP0		.req	q12
	TMP0_L		.req	d24
	TMP0_H		.req	d25
	TMP1		.req	q13
	TMP2		.req	q14
	TMP3		.req	q15

// X = rol32(X ^ Y, Y & (n - 1)) + ROUND_KEY
.macro _rc5_halfround_128bytes	X, Y, ROUND_KEY, n
	veor		\X\()0, \Y\()0
	veor		\X\()1, \Y\()1
	veor		\X\()2, \Y\()2
	veor		\X\()3, \Y\()3
	vdup.u32	q10, CONST_N_MINUS_1
	vdup.u32	q11, CONST_N
	vand		TMP0, \Y\()0, q10
	vand		TMP1, \Y\()1, q10
	vshl.u\n	TMP2, \X\()0, TMP0
	vshl.u\n	TMP3, \X\()1, TMP1
	vsub.s8		TMP0, q11
	vsub.s8		TMP1, q11
	vshl.u\n	\X\()0, TMP0
	vshl.u\n	\X\()1, TMP1
	vorr		\X\()0, TMP2
	vorr		\X\()1, TMP3
	vand		TMP0, \Y\()2, q10
	vand		TMP1, \Y\()3, q10
	vshl.u\n	TMP2, \X\()2, TMP0
	vshl.u\n	TMP3, \X\()3, TMP1
	vsub.s8		TMP0, q11
	vsub.s8		TMP1, q11
	vshl.u\n	\X\()2, TMP0
	vshl.u\n	\X\()3, TMP1
	vorr		\X\()2, TMP2
	vorr.u\n	\X\()3, TMP3
	vadd.u\n	\X\()0, \ROUND_KEY
	vadd.u\n	\X\()1, \ROUND_KEY
	vadd.u\n	\X\()2, \ROUND_KEY
	vadd.u\n	\X\()3, \ROUND_KEY
.endm

// X = ror64(X - *S--, Y & (n - 1)) ^ Y;
.macro _rc5_halfunround_128bytes	X, Y, ROUND_KEY, n
	vdup.u32	q10, CONST_N_MINUS_1
	vdup.u32	q11, CONST_N
	vsub.u\n	\X\()0, \ROUND_KEY
	vsub.u\n	\X\()1, \ROUND_KEY
	vsub.u\n	\X\()2, \ROUND_KEY
	vsub.u\n	\X\()3, \ROUND_KEY

	vand		TMP0, \Y\()0, q10
	vand		TMP1, \Y\()1, q10
	vneg.s8		TMP0, TMP0
	vneg.s8		TMP1, TMP1
	vshl.u\n	TMP2, \X\()0, TMP0
	vshl.u\n	TMP3, \X\()1, TMP1
	vadd.s8		TMP0, q11
	vadd.s8		TMP1, q11
	vshl.u\n	\X\()0, TMP0
	vshl.u\n	\X\()1, TMP1
	vorr		\X\()0, TMP2
	vorr		\X\()1, TMP3
	veor		\X\()0, \Y\()0
	veor		\X\()1, \Y\()1

	vand		TMP0, \Y\()2, q10
	vand		TMP1, \Y\()3, q10
	vneg.s8		TMP0, TMP0
	vneg.s8		TMP1, TMP1
	vshl.u\n	TMP2, \X\()2, TMP0
	vshl.u\n	TMP3, \X\()3, TMP1
	vadd.s8		TMP0, q11
	vadd.s8		TMP1, q11
	vshl.u\n	\X\()2, TMP0
	vshl.u\n	\X\()3, TMP1
	vorr		\X\()2, TMP2
	vorr		\X\()3, TMP3
	veor		\X\()2, \Y\()2
	veor		\X\()3, \Y\()3

.endm

/*
 * _rc5_round_128bytes() - RC5 encryption round on 128 bytes at a time
 *
 * Do one RC5 encryption round on the 128 bytes (8 blocks for RC5-128, 16 for
 * RC5-64) stored in A_0-A_3 and B_0-B_3, using the round keys stored in all
 * lanes of ROUND_KEY_0 and ROUND_KEY_1.  'n' is the lane size: 64 for RC5-128,
 * or 32 for RC5-64.
 */
.macro _rc5_round_128bytes	n

	// A = rol32(A ^ B, B & (n - 1)) + *S++;
	_rc5_halfround_128bytes	A_, B_, ROUND_KEY_0, \n

	// B = rol32(B ^ A, A & (n - 1)) + *S++;
	_rc5_halfround_128bytes	B_, A_, ROUND_KEY_1, \n
.endm

/*
 * _rc5_unround_128bytes() - RC5 decryption round on 128 bytes at a time
 *
 * This is the inverse of _rc5_round_128bytes().
 */
.macro _rc5_unround_128bytes	n

	// B = ror64(B - *S--, A & (n - 1)) ^ A;
	_rc5_halfunround_128bytes B_, A_, ROUND_KEY_0, \n

	// A = ror64(A - *S--, B & (n - 1)) ^ B;
	_rc5_halfunround_128bytes A_, B_, ROUND_KEY_1, \n
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

.macro _load_enc_round_keys	n
.if \n == 64
	vld1.64		ROUND_KEY_0_L, [r12]!
	vmov		ROUND_KEY_0_H, ROUND_KEY_0_L
	vld1.64		ROUND_KEY_1_L, [r12]!
	vmov		ROUND_KEY_1_H, ROUND_KEY_1_L
.else
	vld1.32		{ROUND_KEY_0_L[],ROUND_KEY_0_H[]}, [r12]!
	vld1.32		{ROUND_KEY_1_L[],ROUND_KEY_1_H[]}, [r12]!
.endif
.endm

.macro _load_dec_round_keys	n
.if \n == 64
	vld1.64		ROUND_KEY_0_L, [r12]
	sub		r12, #8
	vmov		ROUND_KEY_0_H, ROUND_KEY_0_L
	vld1.64		ROUND_KEY_1_L, [r12]
	sub		r12, #8
	vmov		ROUND_KEY_1_H, ROUND_KEY_1_L
.else
	vld1.32		{ROUND_KEY_0_L[],ROUND_KEY_0_H[]}, [r12]
	sub		r12, #4
	vld1.32		{ROUND_KEY_1_L[],ROUND_KEY_1_H[]}, [r12]
	sub		r12, #4
.endif
.endm

/*
 * _rc5_xts_crypt() - RC5-XTS encryption/decryption
 *
 * Encrypt or decrypt NBYTES bytes of data from the SRC buffer to the DST buffer
 * using RC5-XTS, specifically the variant with a block size of '2n' and round
 * count given by NROUNDS.  The expanded round keys are given in ROUND_KEYS, and
 * the current XTS tweak value is given in TWEAK.  It's assumed that NBYTES is a
 * nonzero multiple of 128.
 */
.macro _rc5_xts_crypt	n, decrypting
	push		{r4-r9}

	/*
	 * The first four parameters were passed in registers r0-r3.  Load the
	 * additional parameters, which were passed on the stack.
	 */
	ldr		NBYTES, [sp, #24]
	ldr		TWEAK, [sp, #28]

	// Save the callee-saved NEON registers.
	vstmdb		sp!, {q4-q7}

	mov		r9, sp

	mov		CONST_N_MINUS_1, #(\n - 1)
	mov		CONST_N, #\n

	/*
	 * If decrypting, modify the ROUND_KEYS parameter to point to the last
	 * round key rather than the first, since for decryption the round keys
	 * are used in reverse order.
	 */
.if \decrypting
.if \n == 64
	add		ROUND_KEYS, ROUND_KEYS, NROUNDS, lsl #4
	add		ROUND_KEYS, #8
.else
	add		ROUND_KEYS, ROUND_KEYS, NROUNDS, lsl #3
	add		ROUND_KEYS, #4
.endif
.endif

	/*
	 * Allocate stack space to store 128 bytes worth of tweaks.  For
	 * performance, this space is aligned to a 16-byte boundary so that we
	 * can use the load/store instructions that declare 16-byte alignment.
	 */
	sub		sp, #128
	bic		sp, #0xf

.Lnext_128bytes_\@:

.if \n == 64
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
.else
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
.endif


	/*
	 * Load the source blocks into {A,B}[0-3], XOR them with their XTS tweak
	 * values, and save the tweaks on the stack for later.  Then
	 * de-interleave the 'A' and 'B' elements of each block, i.e. make it so
	 * that the A[0-3] registers contain only the second halves of blocks,
	 * and the B[0-3] registers contain only the first halves of blocks.
	 */
	mov		r12, sp
.if \n == 64
	_xts128_precrypt_one	A_0, r12, TMP0
	_xts128_precrypt_one	B_0, r12, TMP0
	_xts128_precrypt_one	A_1, r12, TMP0
	_xts128_precrypt_one	B_1, r12, TMP0
	_xts128_precrypt_one	A_2, r12, TMP0
	_xts128_precrypt_one	B_2, r12, TMP0
	_xts128_precrypt_one	A_3, r12, TMP0
	_xts128_precrypt_one	B_3, r12, TMP0
	vswp		A_0_H, B_0_L
	vswp		A_1_H, B_1_L
	vswp		A_2_H, B_2_L
	vswp		A_3_H, B_3_L
.else
	_xts64_precrypt_two	A_0, r12, TMP0
	_xts64_precrypt_two	B_0, r12, TMP0
	_xts64_precrypt_two	A_1, r12, TMP0
	_xts64_precrypt_two	B_1, r12, TMP0
	_xts64_precrypt_two	A_2, r12, TMP0
	_xts64_precrypt_two	B_2, r12, TMP0
	_xts64_precrypt_two	A_3, r12, TMP0
	_xts64_precrypt_two	B_3, r12, TMP0
	vuzp.32		A_0, B_0
	vuzp.32		A_1, B_1
	vuzp.32		A_2, B_2
	vuzp.32		A_3, B_3
.endif

	// Store the next tweak
.if \n == 64
	vst1.8		{TWEAKV}, [TWEAK]
.else
	vst1.8		{TWEAKV_L}, [TWEAK]
.endif

	// Do the cipher rounds

	mov		r12, ROUND_KEYS
	mov		r8, NROUNDS

.if ! \decrypting
	_load_enc_round_keys	\n
	// A += *S++;
	// B += *S++;
	vadd.u\n	A_0, ROUND_KEY_0
	vadd.u\n	A_1, ROUND_KEY_0
	vadd.u\n	A_2, ROUND_KEY_0
	vadd.u\n	A_3, ROUND_KEY_0
	vadd.u\n	B_0, ROUND_KEY_1
	vadd.u\n	B_1, ROUND_KEY_1
	vadd.u\n	B_2, ROUND_KEY_1
	vadd.u\n	B_3, ROUND_KEY_1
.endif

.Lnext_round_\@:
.if \decrypting
	_load_dec_round_keys	\n
	_rc5_unround_128bytes	\n
.else
	_load_enc_round_keys	\n
	_rc5_round_128bytes	\n
.endif
	subs		r8, r8, #1
	bne		.Lnext_round_\@

.if \decrypting
	_load_dec_round_keys	\n
	// B -= *S--;
	// A -= *S--;
	vsub.u\n	B_0, ROUND_KEY_0
	vsub.u\n	B_1, ROUND_KEY_0
	vsub.u\n	B_2, ROUND_KEY_0
	vsub.u\n	B_3, ROUND_KEY_0
	vsub.u\n	A_0, ROUND_KEY_1
	vsub.u\n	A_1, ROUND_KEY_1
	vsub.u\n	A_2, ROUND_KEY_1
	vsub.u\n	A_3, ROUND_KEY_1
.endif

	// Re-interleave the 'A' and 'B' elements of each block
.if \n == 64
	vswp		A_0_H, B_0_L
	vswp		A_1_H, B_1_L
	vswp		A_2_H, B_2_L
	vswp		A_3_H, B_3_L
.else
	vzip.32		A_0, B_0
	vzip.32		A_1, B_1
	vzip.32		A_2, B_2
	vzip.32		A_3, B_3
.endif

	// XOR the encrypted/decrypted blocks with the tweaks we saved earlier
	mov		r12, sp
	vld1.8		{TMP0, TMP1}, [r12:128]!
	vld1.8		{TMP2, TMP3}, [r12:128]!
	veor		A_0, TMP0
	veor		B_0, TMP1
	veor		A_1, TMP2
	veor		B_1, TMP3
	vld1.8		{TMP0, TMP1}, [r12:128]!
	vld1.8		{TMP2, TMP3}, [r12:128]!
	veor		A_2, TMP0
	veor		B_2, TMP1
	veor		A_3, TMP2
	veor		B_3, TMP3

	// Store the ciphertext in the destination buffer
	vst1.8		{A_0, B_0}, [DST]!
	vst1.8		{A_1, B_1}, [DST]!
	vst1.8		{A_2, B_2}, [DST]!
	vst1.8		{A_3, B_3}, [DST]!

	// Continue if there are more 128-byte chunks remaining, else return
	subs		NBYTES, #128
	bne		.Lnext_128bytes_\@

	mov		sp, r9
	vldmia		sp!, {q4-q7}
	pop		{r4-r9}
	bx		lr
.endm

ENTRY(rc5_128_xts_encrypt_neon)
	_rc5_xts_crypt	n=64, decrypting=0
ENDPROC(rc5_128_xts_encrypt_neon)

ENTRY(rc5_128_xts_decrypt_neon)
	_rc5_xts_crypt	n=64, decrypting=1
ENDPROC(rc5_128_xts_decrypt_neon)

ENTRY(rc5_64_xts_encrypt_neon)
	_rc5_xts_crypt	n=32, decrypting=0
ENDPROC(rc5_64_xts_encrypt_neon)

ENTRY(rc5_64_xts_decrypt_neon)
	_rc5_xts_crypt	n=32, decrypting=1
ENDPROC(rc5_64_xts_decrypt_neon)
