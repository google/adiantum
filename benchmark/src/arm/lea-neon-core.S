/*
 * NEON-accelerated implementation of LEA-XTS
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

	// registers which hold the data being encrypted/decrypted
	X0_A		.req	q0
	X1_A		.req	q1
	X2_A		.req	q2
	X3_A		.req	q3
	X0_B		.req	q4
	X1_B		.req	q5
	X2_B		.req	q6
	X3_B		.req	q7

	// round key registers
	ROUND_KEY_A	.req	q8
	ROUND_KEY_A_L	.req	d16
	ROUND_KEY_A_H	.req	d17
	ROUND_KEY_B	.req	q9
	ROUND_KEY_B_L	.req	d18
	ROUND_KEY_B_H	.req	d19
	ROUND_KEY_C	.req	q10
	ROUND_KEY_C_L	.req	d20
	ROUND_KEY_C_H	.req	d21
	ROUND_KEY_D	.req	q11
	ROUND_KEY_D_L	.req	d22
	ROUND_KEY_D_H	.req	d23

	// current XTS tweak
	TWEAKV		.req	q8
	TWEAKV_L	.req	d16
	TWEAKV_H	.req	d17

	// multiplication table for updating XTS tweaks
	GF128MUL_TABLE	.req	d18

	TMP0_A		.req	q12
	TMP0_A_L	.req	d24
	TMP0_A_H	.req	d25
	TMP0_B		.req	q13
	TMP1_A		.req	q14
	TMP1_B		.req	q15

/*
 * _lea_round_128bytes() - LEA encryption round on 128 bytes at a time
 *
 * Do one LEA encryption round on the 128 bytes (8 blocks) stored in
 * X{0-3}_{A,B}.  'r12' points to the round keys for this round.  The first 4
 * round keys must have already been loaded.
 *
 * Essentially, this implements the C statements:
 *	d = ror32((c ^ RK[4]) + (d ^ RK[5]), 3);
 *	c = ror32((b ^ RK[2]) + (c ^ RK[3]), 5);
 *	b = rol32((a ^ RK[0]) + (b ^ RK[1]), 9);
 *
 * Initially, (a, b, c, d) contain (x0, x1, x2, x3).
 * Afterwards, they contain (x3, x0, x1, x2).
 *
 * The round keys were rearranged to better match the order they're used in this
 * implementation:
 *	LEA-128:       (RK[4], RK[2], RK[1,3,5], RK[0])
 *	LEA-{192,256}: (RK[3], RK[1], RK[4], RK[2], RK[5], RK[0])
 */
.macro _lea_round_128bytes	a, b, c, d, is_lea128, final

	// t0 = c ^ RK[3];
.if \is_lea128
	veor		TMP0_A, \c\()_A, ROUND_KEY_C
	veor		TMP0_B, \c\()_B, ROUND_KEY_C
.else
	veor		TMP0_A, \c\()_A, ROUND_KEY_A
	veor		TMP0_B, \c\()_B, ROUND_KEY_A
	vld1.32		{ROUND_KEY_A_L[],ROUND_KEY_A_H[]}, [r12]!
.endif

	// t1 = b ^ RK[1];
.if \is_lea128
	veor		TMP1_A, \b\()_A, ROUND_KEY_C
	veor		TMP1_B, \b\()_B, ROUND_KEY_C
.else
	veor		TMP1_A, \b\()_A, ROUND_KEY_B
	veor		TMP1_B, \b\()_B, ROUND_KEY_B
	vld1.32		{ROUND_KEY_B_L[],ROUND_KEY_B_H[]}, [r12]!
.endif

	// c ^= RK[4];
.if \is_lea128
	veor		\c\()_A, ROUND_KEY_A
	veor		\c\()_B, ROUND_KEY_A
.else
	veor		\c\()_A, ROUND_KEY_C
	veor		\c\()_B, ROUND_KEY_C
.endif

	// b ^= RK[2];
.if \is_lea128
	veor		\b\()_A, ROUND_KEY_B
	veor		\b\()_B, ROUND_KEY_B
.else
	veor		\b\()_A, ROUND_KEY_D
	veor		\b\()_B, ROUND_KEY_D
.endif

	// d ^= RK[5];
.if \is_lea128
	veor		\d\()_A, ROUND_KEY_C
	veor		\d\()_B, ROUND_KEY_C
.else
	veor		\d\()_A, ROUND_KEY_A
	veor		\d\()_B, ROUND_KEY_A
.endif

.if !\final
	vld1.32		{ROUND_KEY_A_L[],ROUND_KEY_A_H[]}, [r12]!
.endif

	// b += t0;
	vadd.u32	\b\()_A, TMP0_A
	vadd.u32	\b\()_B, TMP0_B

	// t0 = a ^ RK[0];
.if \is_lea128
	veor		TMP0_A, \a\()_A, ROUND_KEY_D
	veor		TMP0_B, \a\()_B, ROUND_KEY_D
.else
	veor		TMP0_A, \a\()_A, ROUND_KEY_B
	veor		TMP0_B, \a\()_B, ROUND_KEY_B
.endif

.if !\final
	vld1.32		{ROUND_KEY_B_L[],ROUND_KEY_B_H[]}, [r12]!
.endif

	// c += d;
	vadd.u32	\c\()_A, \d\()_A
	vadd.u32	\c\()_B, \d\()_B

	// t1 += t0;
	vadd.u32	TMP1_A, TMP0_A
	vadd.u32	TMP1_B, TMP0_B

	// d = ror32(c, 3);
	vshr.u32	\d\()_A, \c\()_A, #3
	vshr.u32	\d\()_B, \c\()_B, #3
.if !\final
	vld1.32		{ROUND_KEY_C_L[],ROUND_KEY_C_H[]}, [r12]!
.endif
	vsli.u32	\d\()_A, \c\()_A, #29
	vsli.u32	\d\()_B, \c\()_B, #29

	// c = ror32(b, 5);
	vshr.u32	\c\()_A, \b\()_A, #5
	vshr.u32	\c\()_B, \b\()_B, #5
.if !\final
	vld1.32		{ROUND_KEY_D_L[],ROUND_KEY_D_H[]}, [r12]!
.endif
	vsli.u32	\c\()_A, \b\()_A, #27
	vsli.u32	\c\()_B, \b\()_B, #27

	// b = rol32(t1, 9);
	vshl.u32	\b\()_A, TMP1_A, #9
	vshl.u32	\b\()_B, TMP1_B, #9
	vsri.u32	\b\()_A, TMP1_A, #23
	vsri.u32	\b\()_B, TMP1_B, #23
.endm

/*
 * _lea_unround_128bytes() - LEA decryption round on 128 bytes at a time
 *
 * This is the inverse of _lea_round_128bytes().  But for this the first four
 * round keys aren't assumed to have been preloaded, and the round keys are
 * given in a slightly different order.
 */
.macro _lea_unround_128bytes	is_lea128

	vld1.32		{ROUND_KEY_A_L[],ROUND_KEY_A_H[]}, [r12]!

	// t0 = ror32(x0, 9);
	// t1 = rol32(x1, 5);
	vshl.u32	TMP0_A, X0_A, #23
	vshl.u32	TMP0_B, X0_B, #23
	vshl.u32	TMP1_A, X1_A, #5
	vshl.u32	TMP1_B, X1_B, #5
	vld1.32		{ROUND_KEY_B_L[],ROUND_KEY_B_H[]}, [r12]!
	vsri.u32	TMP0_A, X0_A, #(32 - 23)
	vsri.u32	TMP0_B, X0_B, #(32 - 23)
	vsri.u32	TMP1_A, X1_A, #(32 - 5)
	vsri.u32	TMP1_B, X1_B, #(32 - 5)

	vld1.32		{ROUND_KEY_C_L[],ROUND_KEY_C_H[]}, [r12]!

	// x1 = x3 ^ k[0];
	// t0 -= x1;
	// x1 = t0 ^ k[1];
	// x0 = rol32(x2, 3);	[interleaved, first half]
	veor		X1_A, X3_A, ROUND_KEY_A
	veor		X1_B, X3_B, ROUND_KEY_A
	vshl.u32	X0_A, X2_A, #3
	vld1.32		{ROUND_KEY_D_L[],ROUND_KEY_D_H[]}, [r12]!
	vsub.u32	TMP0_A, X1_A
	vsub.u32	TMP0_B, X1_B
	vshl.u32	X0_B, X2_B, #3
	veor		X1_A, TMP0_A, ROUND_KEY_B
	veor		X1_B, TMP0_B, ROUND_KEY_B

.if !\is_lea128
	vld1.32		{ROUND_KEY_A_L[],ROUND_KEY_A_H[]}, [r12]!
.endif

	// t0 ^= k[2];
	// t0 = t1 - t0;
	// x2 = t0 ^ k[is_lea128 ? 1 : 3];
	// x0 = rol32(x2, 3);	[interleaved, second half]
	veor		TMP0_A, ROUND_KEY_C
	veor		TMP0_B, ROUND_KEY_C
	vsri.u32	X0_A, X2_A, #(32 - 3)
	vsub.u32	TMP0_A, TMP1_A, TMP0_A
	vsub.u32	TMP0_B, TMP1_B, TMP0_B
	vsri.u32	X0_B, X2_B, #(32 - 3)
.if \is_lea128
	veor		X2_A, TMP0_A, ROUND_KEY_B
	veor		X2_B, TMP0_B, ROUND_KEY_B
.else
	veor		X2_A, TMP0_A, ROUND_KEY_D
	veor		X2_B, TMP0_B, ROUND_KEY_D
.endif

.if !\is_lea128
	vld1.32		{ROUND_KEY_B_L[],ROUND_KEY_B_H[]}, [r12]!
.endif

	// t0 ^= k[is_lea128 ? 3 : 4];
	// t0 = x0 - t0;
	// x0 = x3;
	// x3 = t0 ^ k[is_lea128 ? 1 : 5];
.if \is_lea128
	veor		TMP0_A, ROUND_KEY_D
	veor		TMP0_B, ROUND_KEY_D
.else
	veor		TMP0_A, ROUND_KEY_A
	veor		TMP0_B, ROUND_KEY_A
.endif
	vsub.u32	TMP0_A, X0_A, TMP0_A
	vsub.u32	TMP0_B, X0_B, TMP0_B
	vmov		X0_A, X3_A
	vmov		X0_B, X3_B
	veor		X3_A, TMP0_A, ROUND_KEY_B
	veor		X3_B, TMP0_B, ROUND_KEY_B
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

.macro _lea_xts_crypt	is_lea128, decrypting
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

	/*
	 * Allocate stack space to store 128 bytes worth of tweaks.  For
	 * performance, this space is aligned to a 16-byte boundary so that we
	 * can use the load/store instructions that declare 16-byte alignment.
	 * For Thumb2 compatibility, don't do the 'bic' directly on 'sp'.
	 */
	sub		r12, sp, #128
	bic		r12, #0xf
	mov		sp, r12

.Lnext_128bytes_\@:

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

	mov		r12, ROUND_KEYS
	mov		r6, NROUNDS
.if \decrypting
.Lnext_dec_round_\@:
	_lea_unround_128bytes	is_lea128=\is_lea128
	subs		r6, r6, #1
	bne		.Lnext_dec_round_\@
.else
	vld1.32		{ROUND_KEY_A_L[],ROUND_KEY_A_H[]}, [r12]!
	vld1.32		{ROUND_KEY_B_L[],ROUND_KEY_B_H[]}, [r12]!
	vld1.32		{ROUND_KEY_C_L[],ROUND_KEY_C_H[]}, [r12]!
	vld1.32		{ROUND_KEY_D_L[],ROUND_KEY_D_H[]}, [r12]!
	b 1f
.Lnext_enc_4xround_\@:
	_lea_round_128bytes	a=X3, b=X0, c=X1, d=X2, is_lea128=\is_lea128, final=0
1:
	_lea_round_128bytes	a=X0, b=X1, c=X2, d=X3, is_lea128=\is_lea128, final=0
	_lea_round_128bytes	a=X1, b=X2, c=X3, d=X0, is_lea128=\is_lea128, final=0
	_lea_round_128bytes	a=X2, b=X3, c=X0, d=X1, is_lea128=\is_lea128, final=0
	subs		r6, r6, #4
	bne		.Lnext_enc_4xround_\@
	_lea_round_128bytes	a=X3, b=X0, c=X1, d=X2, is_lea128=\is_lea128, final=1
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

	mov		sp, r7
	vldmia		sp!, {q4-q7}
	pop		{r4-r7}
	bx		lr
.endm

ENTRY(lea_xts_encrypt_neon)
	_lea_xts_crypt	is_lea128=0, decrypting=0
ENDPROC(lea_xts_encrypt_neon)

ENTRY(lea_xts_decrypt_neon)
	_lea_xts_crypt	is_lea128=0, decrypting=1
ENDPROC(lea_xts_decrypt_neon)

/*
 * The following functions assume the LEA-128 key schedule representation that
 * has 4 keys per round, rather than the full 6.  Otherwise they're the same as
 * the above functions.
 */

ENTRY(lea128_xts_encrypt_neon)
	_lea_xts_crypt	is_lea128=1, decrypting=0
ENDPROC(lea128_xts_encrypt_neon)

ENTRY(lea128_xts_decrypt_neon)
	_lea_xts_crypt	is_lea128=1, decrypting=1
ENDPROC(lea128_xts_decrypt_neon)
