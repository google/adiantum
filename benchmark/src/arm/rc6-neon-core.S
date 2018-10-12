/*
 * NEON-accelerated implementation of RC6-XTS
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
	DST		.req	r1	// void *dst
	SRC		.req	r2	// const void *src
	NBYTES		.req	r3	// unsigned int nbytes
	TWEAK		.req	r4	// void *tweak
	ONE		.req	r5
	THIRTY_ONE	.req	r6
	THIRTY_TWO	.req	r7

	// registers which hold the data being encrypted/decrypted
	A_0		.req	q0
	B_0		.req	q1
	C_0		.req	q2
	D_0		.req	q3
	A_1		.req	q4
	B_1		.req	q5
	C_1		.req	q6
	D_1		.req	q7

	T_0		.req	q8
	T_1		.req	q9
	U_0		.req	q10
	U_0_L		.req	d20
	U_0_H		.req	d21
	U_1		.req	q11
	U_1_L		.req	d22
	U_1_H		.req	d23

	TMP_0		.req	q12
	TMP_0_L		.req	d24
	TMP_0_H		.req	d25
	TMP_1		.req	q13
	TMP_1_L		.req	d26
	TMP_1_H		.req	d27
	TMP_2		.req	q14
	TMP_3		.req	q15

	// current XTS tweak value
	TWEAKV		.req	q14
	TWEAKV_L	.req	d28
	TWEAKV_H	.req	d29

	// multiplication table for updating XTS tweaks
	GF128MUL_TABLE	.req	d30

// t = rol32(B * (2*B + 1), 5);
// u = rol32(D * (2*D + 1), 5);
.macro	_rc6_calc_t_and_u	B, D
	vdup.32		T_0, ONE
	vshl.u32	TMP_0, \B\()_0, #1
	vshl.u32	TMP_1, \B\()_1, #1
	vshl.u32	TMP_2, \D\()_0, #1
	vshl.u32	TMP_3, \D\()_1, #1
	vorr		TMP_0, T_0
	vorr		TMP_1, T_0
	vorr		TMP_2, T_0
	vorr		TMP_3, T_0
	vmul.u32	TMP_0, \B\()_0
	vmul.u32	TMP_1, \B\()_1
	vmul.u32	TMP_2, \D\()_0
	vmul.u32	TMP_3, \D\()_1
	vshl.u32	T_0, TMP_0, #5
	vshl.u32	T_1, TMP_1, #5
	vshl.u32	U_0, TMP_2, #5
	vshl.u32	U_1, TMP_3, #5
	vsri.u32	T_0, TMP_0, #(32 - 5)
	vsri.u32	T_1, TMP_1, #(32 - 5)
	vsri.u32	U_0, TMP_2, #(32 - 5)
	vsri.u32	U_1, TMP_3, #(32 - 5)
.endm

.macro _rc6_round_128bytes	A, B, C, D

	_rc6_calc_t_and_u	\B, \D

	// A = rol32(A ^ t, u & 31) + *S++;
	// C = rol32(C ^ u, t & 31) + *S++;

	vdup.32		TMP_0, THIRTY_ONE

	// A ^= t
	// C ^= u
	veor		\A\()_0, T_0
	veor		\A\()_1, T_1
	veor		\C\()_0, U_0
	veor		\C\()_1, U_1

	vdup.32		TMP_2, THIRTY_TWO

	// t &= 31
	// u &= 31
	vand		T_0, TMP_0
	vand		T_1, TMP_0
	vand		U_0, TMP_0
	vand		U_1, TMP_0

	// A = rol32(A, u)
	vshl.u32	TMP_0, \A\()_0, U_0
	vshl.u32	TMP_1, \A\()_1, U_1
	vsub.s8		U_0, TMP_2
	vsub.s8		U_1, TMP_2
	vshl.u32	\A\()_0, U_0
	vshl.u32	\A\()_1, U_1
	vorr		\A\()_0, TMP_0
	vorr		\A\()_1, TMP_1

	vld1.32		{U_0_L[],U_0_H[]}, [r12]!

	// C = rol32(C, t)
	vshl.u32	TMP_0, \C\()_0, T_0
	vshl.u32	TMP_1, \C\()_1, T_1
	vsub.s8		T_0, TMP_2
	vsub.s8		T_1, TMP_2
	vshl.u32	\C\()_0, T_0
	vshl.u32	\C\()_1, T_1
	vorr		\C\()_0, TMP_0
	vorr		\C\()_1, TMP_1

	vld1.32		{U_1_L[],U_1_H[]}, [r12]!

	// A += *S++;
	// C += *S++;
	vadd.u32	\A\()_0, U_0
	vadd.u32	\A\()_1, U_0
	vadd.u32	\C\()_0, U_1
	vadd.u32	\C\()_1, U_1

	// omitted, registers are relabeled instead
	// (A, B, C, D) = (B, C, D, A)
.endm

.macro _rc6_unround_128bytes	A, B, C, D

	_rc6_calc_t_and_u	\B, \D

	vld1.32		{TMP_0_L[],TMP_0_H[]}, [r12]
	sub		r12, #4
	vdup.32		TMP_2, THIRTY_ONE
	vdup.32		TMP_3, THIRTY_TWO
	vld1.32		{TMP_1_L[],TMP_1_H[]}, [r12]
	sub		r12, #4

	// C -= *S--;
	// A -= *S--;
	vsub.u32	\C\()_0, TMP_0
	vsub.u32	\C\()_1, TMP_0
	vsub.u32	\A\()_0, TMP_1
	vsub.u32	\A\()_1, TMP_1

	vst1.8		{T_0, T_1}, [sp:128]

	// C = ror32(C, t & 31) ^ u;
	vneg.s32	T_0, T_0
	vneg.s32	T_1, T_1
	vand		T_0, TMP_2
	vand		T_1, TMP_2
	vshl.u32	TMP_0, \C\()_0, T_0
	vshl.u32	TMP_1, \C\()_1, T_1
	vsub.s32	T_0, TMP_3
	vsub.s32	T_1, TMP_3
	vshl.u32	\C\()_0, T_0
	vshl.u32	\C\()_1, T_1
	vorr		\C\()_0, TMP_0
	vorr		\C\()_1, TMP_1
	veor		\C\()_0, U_0
	veor		\C\()_1, U_1

	vld1.32		{T_0, T_1}, [sp:128]

	// A = ror32(A, u & 31) ^ t;
	vneg.s32	U_0, U_0
	vneg.s32	U_1, U_1
	vand		U_0, TMP_2
	vand		U_1, TMP_2
	vshl.u32	TMP_0, \A\()_0, U_0
	vshl.u32	TMP_1, \A\()_1, U_1
	vsub.s32	U_0, TMP_3
	vsub.s32	U_1, TMP_3
	vshl.u32	\A\()_0, U_0
	vshl.u32	\A\()_1, U_1
	vorr		\A\()_0, TMP_0
	vorr		\A\()_1, TMP_1
	veor		\A\()_0, T_0
	veor		\A\()_1, T_1

	// omitted, registers are relabeled instead
	// (A, B, C, D) = (D, A, B, C)
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

.macro _rc6_xts_crypt	decrypting
	push		{r4-r9}
	mov		r9, sp

	/*
	 * The first four parameters were passed in registers r0-r3.  Load the
	 * additional parameter, which was passed on the stack.
	 */
	ldr		TWEAK, [sp, #24]

	mov		ONE, #1
	mov		THIRTY_ONE, #31
	mov		THIRTY_TWO, #32

	/*
	 * If decrypting, modify the ROUND_KEYS parameter to point to the last
	 * round key rather than the first, since for decryption the round keys
	 * are used in reverse order.
	 */
.if \decrypting
	add		ROUND_KEYS, #(4 * (2 * 20 + 3))
.endif

	/*
	 * Allocate stack space to store 128 bytes worth of tweaks.  For
	 * performance, this space is aligned to a 16-byte boundary so that we
	 * can use the load/store instructions that declare 16-byte alignment.
	 */
	sub		sp, #128
	bic		sp, #0xf

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
	_xts128_precrypt_one	q0, r12, TMP_0
	_xts128_precrypt_one	q1, r12, TMP_0
	_xts128_precrypt_one	q2, r12, TMP_0
	_xts128_precrypt_one	q3, r12, TMP_0
	_xts128_precrypt_one	q4, r12, TMP_0
	_xts128_precrypt_one	q5, r12, TMP_0
	_xts128_precrypt_one	q6, r12, TMP_0
	_xts128_precrypt_one	q7, r12, TMP_0

	// Store the next tweak
	vst1.8		{TWEAKV}, [TWEAK]

	/*
	 * De-interleave the 32-bit words (A, B, C, D) of the blocks such
	 * that A_{0,1} contain all A, B_{0,1} contain all B, and so on.
	 */
	vuzp.32		q0, q1	// => (A, C, A, C) and (B, D, B, D)
	vuzp.32		q2, q3	// => (A, C, A, C) and (B, D, B, D)
	vuzp.32		q4, q5	// => (A, C, A, C) and (B, D, B, D)
	vuzp.32		q6, q7	// => (A, C, A, C) and (B, D, B, D)
	vuzp.32		q0, q2	// => (A, A, A, A) and (C, C, C, C)
	vuzp.32		q1, q3	// => (B, B, B, B) and (D, D, D, D)
	vuzp.32		q4, q6	// => (A, A, A, A) and (C, C, C, C)
	vuzp.32		q5, q7	// => (B, B, B, B) and (D, D, D, D)

	// Do the cipher rounds
	mov		r12, ROUND_KEYS
	mov		r8, #20
.if \decrypting
	// C -= *S--;
	// A -= *S--;
	vld1.32		{TMP_0_L[],TMP_0_H[]}, [r12]
	sub		r12, #4
	vsub.u32	C_0, TMP_0
	vsub.u32	C_1, TMP_0
	vld1.32		{TMP_0_L[],TMP_0_H[]}, [r12]
	sub		r12, #4
	vsub.u32	A_0, TMP_0
	vsub.u32	A_1, TMP_0
	sub		sp, #32
.else
	// B += *S++;
	// D += *S++;
	vld1.32		{TMP_0_L[],TMP_0_H[]}, [r12]!
	vadd.u32	B_0, TMP_0
	vadd.u32	B_1, TMP_0
	vld1.32		{TMP_0_L[],TMP_0_H[]}, [r12]!
	vadd.u32	D_0, TMP_0
	vadd.u32	D_1, TMP_0
.endif

.Lnext_round_\@:
.if \decrypting
	_rc6_unround_128bytes	D, A, B, C
	_rc6_unround_128bytes	C, D, A, B
	_rc6_unround_128bytes	B, C, D, A
	_rc6_unround_128bytes	A, B, C, D
.else
	_rc6_round_128bytes	A, B, C, D
	_rc6_round_128bytes	B, C, D, A
	_rc6_round_128bytes	C, D, A, B
	_rc6_round_128bytes	D, A, B, C
.endif
	subs		r8, #4
	bne		.Lnext_round_\@

.if \decrypting
	// D -= *S--;
	// B -= *S--;
	vld1.32		{TMP_0_L[],TMP_0_H[]}, [r12]
	sub		r12, #4
	vsub.u32	D_0, TMP_0
	vsub.u32	D_1, TMP_0
	vld1.32		{TMP_0_L[],TMP_0_H[]}, [r12]
	sub		r12, #4
	vsub.u32	B_0, TMP_0
	vsub.u32	B_1, TMP_0
	add		sp, #32
.else
	// A += *S++;
	// C += *S++;
	vld1.32		{TMP_0_L[],TMP_0_H[]}, [r12]!
	vadd.u32	A_0, TMP_0
	vadd.u32	A_1, TMP_0
	vld1.32		{TMP_0_L[],TMP_0_H[]}, [r12]!
	vadd.u32	C_0, TMP_0
	vadd.u32	C_1, TMP_0
.endif

	// Re-interleave the 32-bit words (A, B, C, D) of the blocks
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
	vld1.8		{T_0, T_1}, [r12:128]!
	vld1.8		{U_0, U_1}, [r12:128]!
	veor		q0, T_0
	veor		q1, T_1
	veor		q2, U_0
	veor		q3, U_1
	vld1.8		{T_0, T_1}, [r12:128]!
	vld1.8		{U_0, U_1}, [r12:128]!
	veor		q4, T_0
	veor		q5, T_1
	veor		q6, U_0
	veor		q7, U_1

	// Store the ciphertext in the destination buffer
	vst1.8		{q0, q1}, [DST]!
	vst1.8		{q2, q3}, [DST]!
	vst1.8		{q4, q5}, [DST]!
	vst1.8		{q6, q7}, [DST]!

	// Continue if there are more 128-byte chunks remaining, else return
	subs		NBYTES, #128
	bne		.Lnext_128bytes_\@

	mov		sp, r9
	pop		{r4-r9}
	bx		lr
.endm

ENTRY(rc6_xts_encrypt_neon)
	_rc6_xts_crypt	decrypting=0
ENDPROC(rc6_xts_encrypt_neon)

ENTRY(rc6_xts_decrypt_neon)
	_rc6_xts_crypt	decrypting=1
ENDPROC(rc6_xts_decrypt_neon)
