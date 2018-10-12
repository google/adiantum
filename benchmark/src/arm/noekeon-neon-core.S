/*
 * NEON-accelerated implementation of NOEKEON-XTS
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
	KEY		.req	r0	// const u32 key[4]
	DST		.req	r1	// void *dst
	SRC		.req	r2	// const void *src
	NBYTES		.req	r3	// unsigned int nbytes
	TWEAK		.req	r4	// void *tweak

	// registers which hold the data being encrypted/decrypted
	X0_A		.req	q0
	X1_A		.req	q1
	X2_A		.req	q2
	X3_A		.req	q3
	X3_A_L		.req	d6
	X3_A_H		.req	d7
	X0_B		.req	q4
	X1_B		.req	q5
	X2_B		.req	q6
	X3_B		.req	q7
	X3_B_L		.req	d14
	X3_B_H		.req	d15

	// key register
	K		.req	q8
	K_L		.req	d16
	K_H		.req	d17

	// index vectors for vtbl-based rotates
	ROL8_TABLE	.req	d18
	ROR8_TABLE	.req	d19

	TMP0_A		.req	q10
	TMP0_A_L	.req	d20
	TMP0_A_H	.req	d21
	TMP0_B		.req	q11
	TMP0_B_L	.req	d22
	TMP0_B_H	.req	d23
	TMP1_A		.req	q12
	TMP1_A_L	.req	d24
	TMP1_A_H	.req	d25
	TMP1_B		.req	q13
	TMP1_B_L	.req	d26
	TMP1_B_H	.req	d27
	TMP2_A		.req	q14
	TMP2_A_L	.req	d28
	TMP2_A_H	.req	d29
	TMP2_B		.req	q15
	TMP2_B_L	.req	d30
	TMP2_B_H	.req	d31

	// current XTS tweak
	TWEAKV		.req	q14
	TWEAKV_L	.req	d28
	TWEAKV_H	.req	d29

	// multiplication table for updating XTS tweaks
	GF128MUL_TABLE	.req	d30

	// tmp = A ^ B;
	// tmp ^= rol32(tmp, 8) ^ rol32(tmp, 24);
	// C ^= tmp;
	// D ^= tmp;
.macro _noekeon_theta_part	A, B, C, D, t2
	veor		TMP0_A, \A\()_A, \B\()_A
	veor		TMP0_B, \A\()_B, \B\()_B
	vtbl.8		TMP1_A_L, {TMP0_A_L}, ROL8_TABLE
	vtbl.8		TMP1_A_H, {TMP0_A_H}, ROL8_TABLE
	vtbl.8		TMP1_B_L, {TMP0_B_L}, ROL8_TABLE
	vtbl.8		TMP1_B_H, {TMP0_B_H}, ROL8_TABLE
	vtbl.8		\t2\()_A_L, {TMP0_A_L}, ROR8_TABLE
	vtbl.8		\t2\()_A_H, {TMP0_A_H}, ROR8_TABLE
	vtbl.8		\t2\()_B_L, {TMP0_B_L}, ROR8_TABLE
	vtbl.8		\t2\()_B_H, {TMP0_B_H}, ROR8_TABLE
	veor		TMP0_A, TMP1_A
	veor		TMP0_B, TMP1_B
	veor		TMP0_A, \t2\()_A
	veor		TMP0_B, \t2\()_B
	veor		\C\()_A, TMP0_A
	veor		\C\()_B, TMP0_B
	veor		\D\()_A, TMP0_A
	veor		\D\()_B, TMP0_B
.endm

.macro _noekeon_theta	move_x3

	// tmp = x[0] ^ x[2];
	// tmp ^= rol32(tmp, 8) ^ rol32(tmp, 24);
	// x[1] ^= tmp;
	// x[3] ^= tmp;
	_noekeon_theta_part	X0, X2, X1, X3, TMP2

	// x[0] ^= k[0];
	// x[1] ^= k[1];
	// x[2] ^= k[2];
	// x[3] ^= k[3];
	//
	// tmp = x[1] ^ x[3];
	// tmp ^= rol32(tmp, 8) ^ rol32(tmp, 24);
	// x[0] ^= tmp;
	// x[2] ^= tmp;
	vdup.32		TMP0_A, K_L[0]
	vdup.32		TMP0_B, K_L[1]
	vdup.32		TMP1_A, K_H[0]
	vdup.32		TMP1_B, K_H[1]
	veor		X0_A, TMP0_A
	veor		X0_B, TMP0_A
	veor		X1_A, TMP0_B
	veor		X1_B, TMP0_B
	veor		X2_A, TMP1_A
	veor		X2_B, TMP1_A
.if \move_x3
	veor		TMP2_A, X3_A, TMP1_B
	veor		TMP2_B, X3_B, TMP1_B
	_noekeon_theta_part	X1, TMP2, X0, X2, X3
.else
	veor		X3_A, TMP1_B
	veor		X3_B, TMP1_B
	_noekeon_theta_part	X1, X3, X0, X2, TMP2
.endif
.endm

.macro _noekeon_round_128bytes	rc1, rc2

	// x[0] ^= rc1;
.if \rc1 != 0
	vmov.u32	TMP0_A, #\rc1
	veor		X0_A, TMP0_A
	veor		X0_B, TMP0_A
.endif
	_noekeon_theta	move_x3=1

	// x is (X0, X1, X2, TMP2)

	// x[0] ^= rc2;
.if \rc2 != 0
	vmov.u32	TMP0_A, #\rc2
	veor		X0_A, TMP0_A
	veor		X0_B, TMP0_A
.endif

	// Pi1:
	//   x[1] = rol32(x[1], 1);
	//   x[2] = rol32(x[2], 5);
	//   x[3] = rol32(x[3], 2);
	vshl.u32	TMP0_A, X1_A, #1
	vshl.u32	TMP0_B, X1_B, #1
	vshl.u32	TMP1_A, X2_A, #5
	vshl.u32	TMP1_B, X2_B, #5
	vshl.u32	X3_A, TMP2_A, #2
	vshl.u32	X3_B, TMP2_B, #2
	vsri.u32	TMP0_A, X1_A, #(32 - 1)
	vsri.u32	TMP0_B, X1_B, #(32 - 1)
	vsri.u32	TMP1_A, X2_A, #(32 - 5)
	vsri.u32	TMP1_B, X2_B, #(32 - 5)
	vsri.u32	X3_A, TMP2_A, #(32 - 2)
	vsri.u32	X3_B, TMP2_B, #(32 - 2)

	// x is (X0, TMP0, TMP1, X3)

	// Gamma

	// x[1] ^= ~(x[3] | x[2]);
	vorr		X1_A, X3_A, TMP1_A	// using X1 as temp register
	vorr		X1_B, X3_B, TMP1_B
	vmvn		X1_A, X1_A
	vmvn		X1_B, X1_B
	veor		TMP0_A, X1_A
	veor		TMP0_B, X1_B

	// x is (X0, TMP0, TMP1, X3)

	// x[0] ^= x[2] & x[1]
	vand		X1_A, TMP1_A, TMP0_A	// using X1 as temp register
	vand		X1_B, TMP1_B, TMP0_B
	veor		TMP2_A, X0_A, X1_A	// moving x[0] to TMP2
	veor		TMP2_B, X0_B, X1_B

	// x is (TMP2, TMP0, TMP1, X3)

	// tmp = x[3];
	// x[3] = x[0];
	// x[0] = tmp;

	// x is (X3, TMP0, TMP1, TMP2)

	// x[2] ^= x[0] ^ x[1] ^ x[3];
	veor		X1_A, X3_A, TMP0_A	// using X1 as temp register
	veor		X1_B, X3_B, TMP0_B
	veor		TMP1_A, TMP2_A
	veor		TMP1_B, TMP2_B
	veor		TMP1_A, X1_A
	veor		TMP1_B, X1_B

	// x is (X3, TMP0, TMP1, TMP2)

	// x[1] ^= ~(x[3] | x[2]);
	vorr		X0_A, TMP2_A, TMP1_A	// using X0 as temp register
	vorr		X0_B, TMP2_B, TMP1_B
	vmvn		X0_A, X0_A
	vmvn		X0_B, X0_B
	veor		TMP0_A, X0_A
	veor		TMP0_B, X0_B

	// x is (X3, TMP0, TMP1, TMP2)

	// x[0] ^= x[2] & x[1];
	vand		X1_A, TMP1_A, TMP0_A	// using X1 as temp egister
	vand		X1_B, TMP1_B, TMP0_B
	veor		X0_A, X3_A, X1_A	// moving x[0] to X0
	veor		X0_B, X3_B, X1_B

	// x is (X0, TMP0, TMP1, TMP2)

	// Pi2:
	//   x[1] = ror32(x[1], 1);
	//   x[2] = ror32(x[2], 5);
	//   x[3] = ror32(x[3], 2);
	vshr.u32	X1_A, TMP0_A, #1
	vshr.u32	X1_B, TMP0_B, #1
	vshr.u32	X2_A, TMP1_A, #5
	vshr.u32	X2_B, TMP1_B, #5
	vshr.u32	X3_A, TMP2_A, #2
	vshr.u32	X3_B, TMP2_B, #2
	vsli.u32	X1_A, TMP0_A, #(32 - 1)
	vsli.u32	X1_B, TMP0_B, #(32 - 1)
	vsli.u32	X2_A, TMP1_A, #(32 - 5)
	vsli.u32	X2_B, TMP1_B, #(32 - 5)
	vsli.u32	X3_A, TMP2_A, #(32 - 2)
	vsli.u32	X3_B, TMP2_B, #(32 - 2)
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

.macro _noekeon_xts_crypt	decrypting
	push		{r4-r5}
	mov		r5, sp

	/*
	 * The first four parameters were passed in registers r0-r3.  Load the
	 * additional parameter, which was passed on the stack.
	 */
	ldr		TWEAK, [sp, #8]

	// Load the key
	vld1.32		{K}, [KEY]

	// Load the index vectors for vtbl-based 8-bit rotates
	b 1f
	.align 3
.Lrol8_table\@:
	.byte		3, 0, 1, 2, 7, 4, 5, 6
.Lror8_table\@:
	.byte		1, 2, 3, 0, 5, 6, 7, 4
1:
	adr		r12, .Lrol8_table\@
	vld1.8		{ROL8_TABLE}, [r12:64]
	adr		r12, .Lror8_table\@
	vld1.8		{ROR8_TABLE}, [r12:64]

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

	// Convert from big endian
	vrev32.8	q0, q0
	vrev32.8	q1, q1
	vrev32.8	q2, q2
	vrev32.8	q3, q3
	vrev32.8	q4, q4
	vrev32.8	q5, q5
	vrev32.8	q6, q6
	vrev32.8	q7, q7

	// Do the cipher rounds

.if \decrypting
	_noekeon_round_128bytes 0, 0xD4
	_noekeon_round_128bytes 0, 0x6A
	_noekeon_round_128bytes 0, 0x35
	_noekeon_round_128bytes 0, 0x97
	_noekeon_round_128bytes 0, 0xC6
	_noekeon_round_128bytes 0, 0x63
	_noekeon_round_128bytes 0, 0xBC
	_noekeon_round_128bytes 0, 0x5E
	_noekeon_round_128bytes 0, 0x2F
	_noekeon_round_128bytes 0, 0x9A
	_noekeon_round_128bytes 0, 0x4D
	_noekeon_round_128bytes 0, 0xAB
	_noekeon_round_128bytes 0, 0xD8
	_noekeon_round_128bytes 0, 0x6C
	_noekeon_round_128bytes 0, 0x36
	_noekeon_round_128bytes 0, 0x1B

	// Theta(k, x);
	// x[0] ^= 0x80;
	_noekeon_theta	move_x3=0
	vmov.u32	TMP0_A, #0x80
	veor		X0_A, TMP0_A
	veor		X0_B, TMP0_A
.else
	_noekeon_round_128bytes 0x80, 0
	_noekeon_round_128bytes 0x1B, 0
	_noekeon_round_128bytes 0x36, 0
	_noekeon_round_128bytes 0x6C, 0
	_noekeon_round_128bytes 0xD8, 0
	_noekeon_round_128bytes 0xAB, 0
	_noekeon_round_128bytes 0x4D, 0
	_noekeon_round_128bytes 0x9A, 0
	_noekeon_round_128bytes 0x2F, 0
	_noekeon_round_128bytes 0x5E, 0
	_noekeon_round_128bytes 0xBC, 0
	_noekeon_round_128bytes 0x63, 0
	_noekeon_round_128bytes 0xC6, 0
	_noekeon_round_128bytes 0x97, 0
	_noekeon_round_128bytes 0x35, 0
	_noekeon_round_128bytes 0x6A, 0

	// x[0] ^= 0xD4;
	// Theta(k, x);
	mov		r12, #0xD4
	vdup.32		TMP0_A, r12
	veor		X0_A, TMP0_A
	veor		X0_B, TMP0_A
	_noekeon_theta	move_x3=0
.endif

	// Convert from big endian
	vrev32.8	q0, q0
	vrev32.8	q1, q1
	vrev32.8	q2, q2
	vrev32.8	q3, q3
	vrev32.8	q4, q4
	vrev32.8	q5, q5
	vrev32.8	q6, q6
	vrev32.8	q7, q7

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

	mov		sp, r5
	pop		{r4-r5}
	bx		lr
.endm

ENTRY(noekeon_xts_encrypt_neon)
	_noekeon_xts_crypt	decrypting=0
ENDPROC(noekeon_xts_encrypt_neon)

ENTRY(noekeon_xts_decrypt_neon)
	_noekeon_xts_crypt	decrypting=1
ENDPROC(noekeon_xts_decrypt_neon)
