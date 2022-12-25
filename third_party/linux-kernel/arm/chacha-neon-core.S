// SPDX-License-Identifier: GPL-2.0
/*
 * ChaCha 256-bit cipher algorithm, RFC7539, ARM NEON functions
 *
 * Copyright (C) 2016 Linaro, Ltd. <ard.biesheuvel@linaro.org>
 * Copyright (C) 2018 Google LLC
 *
 * Modified by Eric Biggers, 2018:
 *	- various optimizations, e.g. implement 8-bit rotates using 'vtbl.8'
 *	- pass round number as parameter (for ChaCha12 support)
 *	- expose permutation (for XChaCha support)
 *	- add ChaCha-MEM support
 *
 * Originally based on:
 *	ChaCha20 256-bit cipher algorithm, RFC7539, x64 SSE3 functions
 *
 *	Copyright (C) 2015 Martin Willi
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation; either version 2 of the License, or (at your
 *	option) any later version.
 */

 /*
  * NEON doesn't have a rotate instruction.  The alternatives are, more or less:
  *
  * (a)  vshl.u32 + vsri.u32		(needs temporary register)
  * (b)  vshl.u32 + vshr.u32 + vorr	(needs temporary register)
  * (c)  vrev32.16			(16-bit rotations only)
  * (d)  vtbl.8 + vtbl.8		(multiple of 8 bits rotations only,
  *					 needs index vector)
  *
  * ChaCha20 has 16, 12, 8, and 7-bit rotations.  For the 12 and 7-bit
  * rotations, the only choices are (a) and (b).  We use (a) since it takes
  * two-thirds the cycles of (b) on both Cortex-A7 and Cortex-A53.
  *
  * For the 16-bit rotation, we use vrev32.16 since it's consistently fastest
  * and doesn't need a temporary register.
  *
  * For the 8-bit rotation, we use vtbl.8 + vtbl.8.  On Cortex-A7, this sequence
  * is twice as fast as (a), even when doing (a) on multiple registers
  * simultaneously to eliminate the stall between vshl and vsri.  Also, it
  * parallelizes better when temporary registers are scarce.
  *
  * A disadvantage is that on Cortex-A53, the vtbl sequence is the same speed as
  * (a), so the need to load the rotation table actually makes the vtbl method
  * slightly slower overall on that CPU (~1.3% slower ChaCha20).  Still, it
  * seems to be a good compromise to get a more significant speed boost on some
  * CPUs, e.g. ~4.8% faster ChaCha20 on Cortex-A7.
  */

#include "asm_common.h"

#define USE_VTBL 1

	.text
	.fpu		neon
	.align		5

	q0l		.req	d0
	q0h		.req	d1
	q1l		.req	d2
	q1h		.req	d3
	q2l		.req	d4
	q2h		.req	d5
	q3l		.req	d6
	q3h		.req	d7
	q4l		.req	d8
	q4h		.req	d9
	q5l		.req	d10
	q5h		.req	d11
	q6l		.req	d12
	q6h		.req	d13
	q7l		.req	d14
	q7h		.req	d15
	q8l		.req	d16
	q8h		.req	d17
	q9l		.req	d18
	q9h		.req	d19
	q10l		.req	d20
	q10h		.req	d21
	q11l		.req	d22
	q11h		.req	d23
	q12l		.req	d24
	q12h		.req	d25
	q13l		.req	d26
	q13h		.req	d27
	q14l		.req	d28
	q14h		.req	d29
	q15l		.req	d30
	q15h		.req	d31

/*
 * _chacha_perm - permute one ChaCha block
 *
 * Permute one 64-byte block where the state matrix is stored in the four NEON
 * registers q0-q3.  It performs matrix operation on four words in parallel, but
 * requireds shuffling to rearrange the words after each round.
 *
 * The round count is given in r3.
 *
 * Clobbers: r3, ip, q4-q5
 */
.macro	_chacha_perm

	adr		ip, .Lrol8_table
	vld1.8		{d10}, [ip, :64]

.Ldoubleround_\@:
	// x0 += x1, x3 = rotl32(x3 ^ x0, 16)
	vadd.i32	q0, q0, q1
	veor		q3, q3, q0
	vrev32.16	q3, q3

	// x2 += x3, x1 = rotl32(x1 ^ x2, 12)
	vadd.i32	q2, q2, q3
	veor		q4, q1, q2
	vshl.u32	q1, q4, #12
	vsri.u32	q1, q4, #20

	// x0 += x1, x3 = rotl32(x3 ^ x0, 8)
	vadd.i32	q0, q0, q1
	veor		q3, q3, q0
	vtbl.8		d6, {d6}, d10
	vtbl.8		d7, {d7}, d10

	// x2 += x3, x1 = rotl32(x1 ^ x2, 7)
	vadd.i32	q2, q2, q3
	veor		q4, q1, q2
	vshl.u32	q1, q4, #7
	vsri.u32	q1, q4, #25

	// x1 = shuffle32(x1, MASK(0, 3, 2, 1))
	vext.8		q1, q1, q1, #4
	// x2 = shuffle32(x2, MASK(1, 0, 3, 2))
	vext.8		q2, q2, q2, #8
	// x3 = shuffle32(x3, MASK(2, 1, 0, 3))
	vext.8		q3, q3, q3, #12

	// x0 += x1, x3 = rotl32(x3 ^ x0, 16)
	vadd.i32	q0, q0, q1
	veor		q3, q3, q0
	vrev32.16	q3, q3

	// x2 += x3, x1 = rotl32(x1 ^ x2, 12)
	vadd.i32	q2, q2, q3
	veor		q4, q1, q2
	vshl.u32	q1, q4, #12
	vsri.u32	q1, q4, #20

	// x0 += x1, x3 = rotl32(x3 ^ x0, 8)
	vadd.i32	q0, q0, q1
	veor		q3, q3, q0
	vtbl.8		d6, {d6}, d10
	vtbl.8		d7, {d7}, d10

	// x2 += x3, x1 = rotl32(x1 ^ x2, 7)
	vadd.i32	q2, q2, q3
	veor		q4, q1, q2
	vshl.u32	q1, q4, #7
	vsri.u32	q1, q4, #25

	// x1 = shuffle32(x1, MASK(2, 1, 0, 3))
	vext.8		q1, q1, q1, #12
	// x2 = shuffle32(x2, MASK(1, 0, 3, 2))
	vext.8		q2, q2, q2, #8
	// x3 = shuffle32(x3, MASK(0, 3, 2, 1))
	vext.8		q3, q3, q3, #4

	subs		r3, r3, #2
	bne		.Ldoubleround_\@
.endm

/*
 * _chacha_perm4 - permute four ChaCha blocks
 *
 * Permute four 64-byte blocks where the state matrices are stored in the 16
 * NEON registers q0-q15.  q0 contains the x[0] value for each block, q1
 * contains the x[1] values, and so on.
 *
 * The round count is given in r3.  'sp' must point to a 32-byte aligned 32-byte
 * temporary buffer.  'ip' must point to .Lrol8_table or equivalent.
 *
 * Clobbers: r3, 32 bytes at 'sp'
 */
.macro _chacha_perm4

	b		1f

.Ldoubleround4_\@:
	vld1.32		{q8-q9}, [sp, :256]
1:
	// x0 += x4, x12 = rotl32(x12 ^ x0, 16)
	// x1 += x5, x13 = rotl32(x13 ^ x1, 16)
	// x2 += x6, x14 = rotl32(x14 ^ x2, 16)
	// x3 += x7, x15 = rotl32(x15 ^ x3, 16)
	vadd.i32	q0, q0, q4
	vadd.i32	q1, q1, q5
	vadd.i32	q2, q2, q6
	vadd.i32	q3, q3, q7

	veor		q12, q12, q0
	veor		q13, q13, q1
	veor		q14, q14, q2
	veor		q15, q15, q3

	vrev32.16	q12, q12
	vrev32.16	q13, q13
	vrev32.16	q14, q14
	vrev32.16	q15, q15

	// x8 += x12, x4 = rotl32(x4 ^ x8, 12)
	// x9 += x13, x5 = rotl32(x5 ^ x9, 12)
	// x10 += x14, x6 = rotl32(x6 ^ x10, 12)
	// x11 += x15, x7 = rotl32(x7 ^ x11, 12)
	vadd.i32	q8, q8, q12
	vadd.i32	q9, q9, q13
	vadd.i32	q10, q10, q14
	vadd.i32	q11, q11, q15

	vst1.32		{q8-q9}, [sp, :256]

	veor		q8, q4, q8
	veor		q9, q5, q9
	vshl.u32	q4, q8, #12
	vshl.u32	q5, q9, #12
	vsri.u32	q4, q8, #20
	vsri.u32	q5, q9, #20

	veor		q8, q6, q10
	veor		q9, q7, q11
	vshl.u32	q6, q8, #12
	vshl.u32	q7, q9, #12
	vsri.u32	q6, q8, #20
	vsri.u32	q7, q9, #20

	// x0 += x4, x12 = rotl32(x12 ^ x0, 8)
	// x1 += x5, x13 = rotl32(x13 ^ x1, 8)
	// x2 += x6, x14 = rotl32(x14 ^ x2, 8)
	// x3 += x7, x15 = rotl32(x15 ^ x3, 8)
#if USE_VTBL
	vld1.8		{d16}, [ip, :64]
	vadd.i32	q0, q0, q4
	vadd.i32	q1, q1, q5
	vadd.i32	q2, q2, q6
	vadd.i32	q3, q3, q7

	veor		q12, q12, q0
	veor		q13, q13, q1
	veor		q14, q14, q2
	veor		q15, q15, q3

	vtbl.8		d24, {d24}, d16
	vtbl.8		d25, {d25}, d16
	vtbl.8		d26, {d26}, d16
	vtbl.8		d27, {d27}, d16
	vtbl.8		d28, {d28}, d16
	vtbl.8		d29, {d29}, d16
	vtbl.8		d30, {d30}, d16
	vtbl.8		d31, {d31}, d16
#else
	vadd.i32	q0, q0, q4
	vadd.i32	q1, q1, q5
	vadd.i32	q2, q2, q6
	vadd.i32	q3, q3, q7

	veor		q8, q12, q0
	veor		q9, q13, q1
	vshl.u32	q12, q8, #8
	vshl.u32	q13, q9, #8
	vsri.u32	q12, q8, #24
	vsri.u32	q13, q9, #24

	veor		q8, q14, q2
	veor		q9, q15, q3
	vshl.u32	q14, q8, #8
	vshl.u32	q15, q9, #8
	vsri.u32	q14, q8, #24
	vsri.u32	q15, q9, #24
#endif

	vld1.32		{q8-q9}, [sp, :256]

	// x8 += x12, x4 = rotl32(x4 ^ x8, 7)
	// x9 += x13, x5 = rotl32(x5 ^ x9, 7)
	// x10 += x14, x6 = rotl32(x6 ^ x10, 7)
	// x11 += x15, x7 = rotl32(x7 ^ x11, 7)
	vadd.i32	q8, q8, q12
	vadd.i32	q9, q9, q13
	vadd.i32	q10, q10, q14
	vadd.i32	q11, q11, q15

	vst1.32		{q8-q9}, [sp, :256]

	veor		q8, q4, q8
	veor		q9, q5, q9
	vshl.u32	q4, q8, #7
	vshl.u32	q5, q9, #7
	vsri.u32	q4, q8, #25
	vsri.u32	q5, q9, #25

	veor		q8, q6, q10
	veor		q9, q7, q11
	vshl.u32	q6, q8, #7
	vshl.u32	q7, q9, #7
	vsri.u32	q6, q8, #25
	vsri.u32	q7, q9, #25

	vld1.32		{q8-q9}, [sp, :256]

	// x0 += x5, x15 = rotl32(x15 ^ x0, 16)
	// x1 += x6, x12 = rotl32(x12 ^ x1, 16)
	// x2 += x7, x13 = rotl32(x13 ^ x2, 16)
	// x3 += x4, x14 = rotl32(x14 ^ x3, 16)
	vadd.i32	q0, q0, q5
	vadd.i32	q1, q1, q6
	vadd.i32	q2, q2, q7
	vadd.i32	q3, q3, q4

	veor		q15, q15, q0
	veor		q12, q12, q1
	veor		q13, q13, q2
	veor		q14, q14, q3

	vrev32.16	q15, q15
	vrev32.16	q12, q12
	vrev32.16	q13, q13
	vrev32.16	q14, q14

	// x10 += x15, x5 = rotl32(x5 ^ x10, 12)
	// x11 += x12, x6 = rotl32(x6 ^ x11, 12)
	// x8 += x13, x7 = rotl32(x7 ^ x8, 12)
	// x9 += x14, x4 = rotl32(x4 ^ x9, 12)
	vadd.i32	q10, q10, q15
	vadd.i32	q11, q11, q12
	vadd.i32	q8, q8, q13
	vadd.i32	q9, q9, q14

	vst1.32		{q8-q9}, [sp, :256]

	veor		q8, q7, q8
	veor		q9, q4, q9
	vshl.u32	q7, q8, #12
	vshl.u32	q4, q9, #12
	vsri.u32	q7, q8, #20
	vsri.u32	q4, q9, #20

	veor		q8, q5, q10
	veor		q9, q6, q11
	vshl.u32	q5, q8, #12
	vshl.u32	q6, q9, #12
	vsri.u32	q5, q8, #20
	vsri.u32	q6, q9, #20

	// x0 += x5, x15 = rotl32(x15 ^ x0, 8)
	// x1 += x6, x12 = rotl32(x12 ^ x1, 8)
	// x2 += x7, x13 = rotl32(x13 ^ x2, 8)
	// x3 += x4, x14 = rotl32(x14 ^ x3, 8)
#if USE_VTBL
	vld1.8		{d16}, [ip, :64]
	vadd.i32	q0, q0, q5
	vadd.i32	q1, q1, q6
	vadd.i32	q2, q2, q7
	vadd.i32	q3, q3, q4

	veor		q15, q15, q0
	veor		q12, q12, q1
	veor		q13, q13, q2
	veor		q14, q14, q3

	vtbl.8		d30, {d30}, d16
	vtbl.8		d31, {d31}, d16
	vtbl.8		d24, {d24}, d16
	vtbl.8		d25, {d25}, d16
	vtbl.8		d26, {d26}, d16
	vtbl.8		d27, {d27}, d16
	vtbl.8		d28, {d28}, d16
	vtbl.8		d29, {d29}, d16
#else
	vadd.i32	q0, q0, q5
	vadd.i32	q1, q1, q6
	vadd.i32	q2, q2, q7
	vadd.i32	q3, q3, q4
	veor		q8, q15, q0
	veor		q9, q12, q1
	vshl.u32	q15, q8, #8
	vshl.u32	q12, q9, #8
	vsri.u32	q15, q8, #24
	vsri.u32	q12, q9, #24
	veor		q8, q13, q2
	veor		q9, q14, q3
	vshl.u32	q13, q8, #8
	vshl.u32	q14, q9, #8
	vsri.u32	q13, q8, #24
	vsri.u32	q14, q9, #24
#endif

	vld1.32		{q8-q9}, [sp, :256]

	// x10 += x15, x5 = rotl32(x5 ^ x10, 7)
	// x11 += x12, x6 = rotl32(x6 ^ x11, 7)
	// x8 += x13, x7 = rotl32(x7 ^ x8, 7)
	// x9 += x14, x4 = rotl32(x4 ^ x9, 7)
	vadd.i32	q10, q10, q15
	vadd.i32	q11, q11, q12
	vadd.i32	q8, q8, q13
	vadd.i32	q9, q9, q14

	vst1.32		{q8-q9}, [sp, :256]

	veor		q8, q7, q8
	veor		q9, q4, q9
	vshl.u32	q7, q8, #7
	vshl.u32	q4, q9, #7
	vsri.u32	q7, q8, #25
	vsri.u32	q4, q9, #25

	veor		q8, q5, q10
	veor		q9, q6, q11
	vshl.u32	q5, q8, #7
	vshl.u32	q6, q9, #7
	vsri.u32	q5, q8, #25
	vsri.u32	q6, q9, #25

	subs		r3, r3, #2
	bne		.Ldoubleround4_\@
.endm

	// A = ror32(A, n) ^ E;  E -= I;
	// B = ror32(B, n) ^ F;  F -= J;
	// C = ror32(C, n) ^ G;  G -= K;
	// D = ror32(D, n) ^ H;  H -= L;
.macro _chacha_invquarterround4	A, B, C, D,  E, F, G, H,  I, J, K, L,  T1, T2, n
	vst1.8		{\T1, \T2}, [sp, :256]
	vshr.u32	\T1, \A, #\n
	vshr.u32	\T2, \B, #\n
	vsli.u32	\T1, \A, #(32 - \n)
	vsli.u32	\T2, \B, #(32 - \n)
	veor		\A, \T1, \E
	veor		\B, \T2, \F
	vshr.u32	\T1, \C, #\n
	vshr.u32	\T2, \D, #\n
	vsub.u32	\E, \I
	vsli.u32	\T1, \C, #(32 - \n)
	vsli.u32	\T2, \D, #(32 - \n)
	vsub.u32	\F, \J
	veor		\C, \T1, \G
	veor		\D, \T2, \H
	vld1.8		{\T1, \T2}, [sp, :256]
	vsub.u32	\G, \K
	vsub.u32	\H, \L
.endm

	// A = ror32(A, 8) ^ E;  E -= I;
	// B = ror32(B, 8) ^ F;  F -= J;
	// C = ror32(C, 8) ^ G;  G -= K;
	// D = ror32(D, 8) ^ H;  H -= L;
.macro _chacha_invquarterround4_ror8   A, B, C, D,  E, F, G, H,  I, J, K, L,  T1
	vst1.8		{\T1\()l}, [sp, :64]
	vld1.8		{\T1\()l}, [ip, :64]
	vtbl.8		\A\()l, {\A\()l}, \T1\()l
	vtbl.8		\A\()h, {\A\()h}, \T1\()l
	vtbl.8		\B\()l, {\B\()l}, \T1\()l
	vtbl.8		\B\()h, {\B\()h}, \T1\()l
	vtbl.8		\C\()l, {\C\()l}, \T1\()l
	vtbl.8		\C\()h, {\C\()h}, \T1\()l
	vtbl.8		\D\()l, {\D\()l}, \T1\()l
	vtbl.8		\D\()h, {\D\()h}, \T1\()l
	vld1.8		{\T1\()l}, [sp, :64]
	veor		\A, \E
	veor		\B, \F
	veor		\C, \G
	veor		\D, \H
	vsub.u32	\E, \I
	vsub.u32	\F, \J
	vsub.u32	\G, \K
	vsub.u32	\H, \L
.endm

	// A = ror32(A, 16) ^ E;  E -= I;
	// B = ror32(B, 16) ^ F;  F -= J;
	// C = ror32(C, 16) ^ G;  G -= K;
	// D = ror32(D, 16) ^ H;  H -= L;
.macro _chacha_invquarterround4_ror16	A, B, C, D,   E, F, G, H,   I, J, K, L
	vrev32.16	\A, \A
	vrev32.16	\B, \B
	vrev32.16	\C, \C
	vrev32.16	\D, \D
	veor		\A, \E
	veor		\B, \F
	veor		\C, \G
	veor		\D, \H
	vsub.u32	\E, \I
	vsub.u32	\F, \J
	vsub.u32	\G, \K
	vsub.u32	\H, \L
.endm

/*
 * _chacha_invperm4 - inverse permute four ChaCha blocks
 *
 * Like _chacha_perm4, but inverts the permutation.
 */
.macro _chacha_invperm4

	adr		ip, .Lror8_table\@
	b		1f
	.align		3
.Lror8_table\@:
	.byte		1, 2, 3, 0, 5, 6, 7, 4
1:

.Ldoubleround4_\@:
	_chacha_invquarterround4	q5, q6, q7, q4,      q10, q11, q8, q9, \
		q15, q12, q13, q14,	q0, q1, 7

	_chacha_invquarterround4_ror8	q15, q12, q13, q14,  q0, q1, q2, q3, \
		q5, q6, q7, q4,		q8

	_chacha_invquarterround4	q5, q6, q7, q4,      q10, q11, q8, q9, \
		q15, q12, q13, q14,	q0, q1, 12

	_chacha_invquarterround4_ror16	q15, q12, q13, q14,  q0, q1, q2, q3,\
		q5, q6, q7, q4

	_chacha_invquarterround4	q4, q5, q6, q7,	     q8, q9, q10, q11, \
		q12, q13, q14, q15,	q0, q1, 7

	_chacha_invquarterround4_ror8	q12, q13, q14, q15,  q0, q1, q2, q3, \
		q4, q5, q6, q7,		q8

	_chacha_invquarterround4	q4, q5, q6, q7,      q8, q9, q10, q11, \
		q12, q13, q14, q15,     q0, q1, 12

	_chacha_invquarterround4_ror16	q12, q13, q14, q15,  q0, q1, q2, q3, \
		q4, q5, q6, q7

	subs		r3, r3, #2
	bne		.Ldoubleround4_\@
.endm

ENTRY(chacha_block_xor_neon)
	// r0: Input state matrix, s
	// r1: 1 data block output, o
	// r2: 1 data block input, i
	// r3: nrounds

	// Save the callee-saved NEON registers.
	vstmdb		sp!, {q4-q7}

	// x0..3 = s0..3
	add		ip, r0, #0x20
	vld1.32		{q0-q1}, [r0]
	vld1.32		{q2-q3}, [ip]

	vmov		q8, q0
	vmov		q9, q1
	vmov		q10, q2
	vmov		q11, q3

	_chacha_perm

	add		ip, r2, #0x20
	vld1.8		{q4-q5}, [r2]
	vld1.8		{q6-q7}, [ip]

	// o0 = i0 ^ (x0 + s0)
	vadd.i32	q0, q0, q8
	veor		q0, q0, q4

	// o1 = i1 ^ (x1 + s1)
	vadd.i32	q1, q1, q9
	veor		q1, q1, q5

	// o2 = i2 ^ (x2 + s2)
	vadd.i32	q2, q2, q10
	veor		q2, q2, q6

	// o3 = i3 ^ (x3 + s3)
	vadd.i32	q3, q3, q11
	veor		q3, q3, q7

	add		ip, r1, #0x20
	vst1.8		{q0-q1}, [r1]
	vst1.8		{q2-q3}, [ip]

	vldmia		sp!, {q4-q7}
	bx		lr
ENDPROC(chacha_block_xor_neon)

	.align		4
.Lctrinc:	.word	0, 1, 2, 3
.Lrol8_table:	.byte	3, 0, 1, 2, 7, 4, 5, 6

	.align		5
ENTRY(chacha_4block_xor_neon)
	vstmdb		sp!, {q4-q7}		// Save callee-saved NEON registers
	push		{r4-r5}
	mov		r4, sp			// preserve the stack pointer
	sub		ip, sp, #0x20		// allocate a 32 byte buffer
	bic		ip, ip, #0x1f		// aligned to 32 bytes
	mov		sp, ip

	// r0: Input state matrix, s
	// r1: 4 data blocks output, o
	// r2: 4 data blocks input, i
	// r3: nrounds

	//
	// This function encrypts four consecutive ChaCha20 blocks by loading
	// the state matrix in NEON registers four times. The algorithm performs
	// each operation on the corresponding word of each state matrix, hence
	// requires no word shuffling. The words are re-interleaved before the
	// final addition of the original state and the XORing step.
	//

	// x0..15[0-3] = s0..15[0-3]
	add		ip, r0, #0x20
	vld1.32		{q0-q1}, [r0]
	vld1.32		{q2-q3}, [ip]

	adr		r5, .Lctrinc
	vdup.32		q15, d7[1]
	vdup.32		q14, d7[0]
	vld1.32		{q4}, [r5, :128]
	vdup.32		q13, d6[1]
	vdup.32		q12, d6[0]
	vdup.32		q11, d5[1]
	vdup.32		q10, d5[0]
	vadd.u32	q12, q12, q4		// x12 += counter values 0-3
	vdup.32		q9, d4[1]
	vdup.32		q8, d4[0]
	vdup.32		q7, d3[1]
	vdup.32		q6, d3[0]
	vdup.32		q5, d2[1]
	vdup.32		q4, d2[0]
	vdup.32		q3, d1[1]
	vdup.32		q2, d1[0]
	vdup.32		q1, d0[1]
	vdup.32		q0, d0[0]

#if USE_VTBL
	adr		ip, .Lrol8_table
#endif
	_chacha_perm4

	// x0..7[0-3] are in q0-q7, x10..15[0-3] are in q10-q15.
	// x8..9[0-3] are on the stack.

	// Re-interleave the words in the first two rows of each block (x0..7).
	// Also add the counter values 0-3 to x12[0-3].
	  vld1.32	{q8}, [r5, :128]	// load counter values 0-3
	vzip.32		q0, q1			// => (0 1 0 1) (0 1 0 1)
	vzip.32		q2, q3			// => (2 3 2 3) (2 3 2 3)
	vzip.32		q4, q5			// => (4 5 4 5) (4 5 4 5)
	vzip.32		q6, q7			// => (6 7 6 7) (6 7 6 7)
	  vadd.u32	q12, q8			// x12 += counter values 0-3
	vswp		d1, d4
	vswp		d3, d6
	  vld1.32	{q8-q9}, [r0]!		// load s0..7
	vswp		d9, d12
	vswp		d11, d14

	// Swap q1 and q4 so that we'll free up consecutive registers (q0-q1)
	// after XORing the first 32 bytes.
	vswp		q1, q4

	// First two rows of each block are (q0 q1) (q2 q6) (q4 q5) (q3 q7)

	// x0..3[0-3] += s0..3[0-3]	(add orig state to 1st row of each block)
	vadd.u32	q0, q0, q8
	vadd.u32	q2, q2, q8
	vadd.u32	q4, q4, q8
	vadd.u32	q3, q3, q8

	// x4..7[0-3] += s4..7[0-3]	(add orig state to 2nd row of each block)
	vadd.u32	q1, q1, q9
	vadd.u32	q6, q6, q9
	vadd.u32	q5, q5, q9
	vadd.u32	q7, q7, q9

	// XOR first 32 bytes using keystream from first two rows of first block
	vld1.8		{q8-q9}, [r2]!
	veor		q8, q8, q0
	veor		q9, q9, q1
	vst1.8		{q8-q9}, [r1]!

	// Re-interleave the words in the last two rows of each block (x8..15).
	vld1.32		{q8-q9}, [sp, :256]
	vzip.32		q12, q13	// => (12 13 12 13) (12 13 12 13)
	vzip.32		q14, q15	// => (14 15 14 15) (14 15 14 15)
	vzip.32		q8, q9		// => (8 9 8 9) (8 9 8 9)
	vzip.32		q10, q11	// => (10 11 10 11) (10 11 10 11)
	  vld1.32	{q0-q1}, [r0]	// load s8..15
	vswp		d25, d28
	vswp		d27, d30
	vswp		d17, d20
	vswp		d19, d22

	// Last two rows of each block are (q8 q12) (q10 q14) (q9 q13) (q11 q15)

	// x8..11[0-3] += s8..11[0-3]	(add orig state to 3rd row of each block)
	vadd.u32	q8,  q8,  q0
	vadd.u32	q10, q10, q0
	vadd.u32	q9,  q9,  q0
	vadd.u32	q11, q11, q0

	// x12..15[0-3] += s12..15[0-3] (add orig state to 4th row of each block)
	vadd.u32	q12, q12, q1
	vadd.u32	q14, q14, q1
	vadd.u32	q13, q13, q1
	vadd.u32	q15, q15, q1

	// XOR the rest of the data with the keystream

	vld1.8		{q0-q1}, [r2]!
	veor		q0, q0, q8
	veor		q1, q1, q12
	vst1.8		{q0-q1}, [r1]!

	vld1.8		{q0-q1}, [r2]!
	veor		q0, q0, q2
	veor		q1, q1, q6
	vst1.8		{q0-q1}, [r1]!

	vld1.8		{q0-q1}, [r2]!
	veor		q0, q0, q10
	veor		q1, q1, q14
	vst1.8		{q0-q1}, [r1]!

	vld1.8		{q0-q1}, [r2]!
	veor		q0, q0, q4
	veor		q1, q1, q5
	vst1.8		{q0-q1}, [r1]!

	vld1.8		{q0-q1}, [r2]!
	veor		q0, q0, q9
	veor		q1, q1, q13
	vst1.8		{q0-q1}, [r1]!

	vld1.8		{q0-q1}, [r2]!
	veor		q0, q0, q3
	veor		q1, q1, q7
	vst1.8		{q0-q1}, [r1]!

	vld1.8		{q0-q1}, [r2]
	  mov		sp, r4		// restore original stack pointer
	veor		q0, q0, q11
	veor		q1, q1, q15
	vst1.8		{q0-q1}, [r1]

	pop		{r4-r5}
	vldmia		sp!, {q4-q7}
	bx		lr
ENDPROC(chacha_4block_xor_neon)

ENTRY(chacha_perm_neon)
	// Save the callee-saved NEON registers that are used.
	vstmdb		sp!, {q4-q5}

	// r0: Input state matrix, s
	// r1: nrounds
	add		ip, r0, #0x20
	vld1.32		{q0-q1}, [r0]
	vld1.32		{q2-q3}, [ip]

	mov		r3, r1
	_chacha_perm

	vst1.8		{q0-q1}, [r0]!
	vst1.8		{q2-q3}, [r0]

	vldmia		sp!, {q4-q5}
	bx		lr
ENDPROC(chacha_perm_neon)

.macro _next_mask	A, B, C, D, E
	vext.8		\A, \B, #4
	vext.8		\B, \C, #4
	vext.8		\C, \D, #4
	vext.8		\D, \E, #4
	vext.8		\E, \E, #4
.endm

/*
 * _chacha_mem_crypt_4block_neon - Encrypt or decrypt 4 blocks with ChaCha-MEM
 *
 * r0 = mask
 * r1 = dst
 * r2 = src
 * r3 = nrounds
 */
.macro _chacha_mem_crypt_4block_neon	decrypting
	// Save the callee-saved NEON registers.
	vstmdb		sp!, {q4-q7}

	// 32-byte align the stack
	push		{r4}
	mov		r4, sp
	bic		sp, #31

	// Load mask into (q0, q4, q8, q12) and calculate next 4 mask words:
	//   rol32(mask[0..3], 5) ^ (mask[3..6] >> 7)
	mov		ip, r0
	vld1.8		{q0}, [ip]!
	vld1.8		{q4}, [ip]!
	sub		sp, #32
	vext.8		q1, q0, q4, #12
	vshl.u32	q5, q0, #5
	vld1.8		{q8}, [ip]!
	vsri.u32	q5, q0, #(32 - 5)
	vshr.u32	q1, #7
	veor		q1, q5
	vld1.8		{q12}, [ip]
	vst1.8		{q1}, [sp, :128]
	sub		sp, #128

	// Load first source block, XOR with mask, spill to stack
	vld1.8		{q10-q11}, [r2]!
	veor		q10, q0
	veor		q11, q4
	vst1.8		{q10-q11}, [sp, :256]!
	vld1.8		{q14-q15}, [r2]!
	veor		q14, q8
	veor		q15, q12
	vst1.8		{q14-q15}, [sp, :256]!

	_next_mask	q0, q4, q8, q12, q1

	// Load second source block, XOR with mask, spill to stack
	vld1.8		{q10-q11}, [r2]!
	veor		q10, q0
	veor		q11, q4
	vst1.8		{q10-q11}, [sp, :256]!
	vld1.8		{q14-q15}, [r2]!
	veor		q14, q8
	veor		q15, q12
	vst1.8		{q14-q15}, [sp, :256]

	sub		sp, #96

	_next_mask	q0, q4, q8, q12, q1

	// Load third source block, XOR with mask
	vld1.8		{q2}, [r2]!
	veor		q2, q0
	vld1.8		{q6}, [r2]!
	veor		q6, q4
	vld1.8		{q10}, [r2]!
	veor		q10, q8
	vld1.8		{q14}, [r2]!
	veor		q14, q12

	_next_mask	q0, q4, q8, q12, q1

	// Load fourth source block, XOR with mask
	vld1.8		{q3}, [r2]!
	veor		q3, q0
	vld1.8		{q7}, [r2]!
	veor		q7, q4
	vld1.8		{q11}, [r2]!
	veor		q11, q8
	vld1.8		{q15}, [r2]
	veor		q15, q12

	// Reload XOR'ed first source block, replacing mask
	vld1.8		{q0}, [sp, :128]!
	vld1.8		{q4}, [sp, :128]!
	vld1.8		{q8}, [sp, :128]!
	vld1.8		{q12}, [sp, :128]!

	// Reload XOR'ed second source block
	vld1.8		{q1}, [sp, :128]!
	vld1.8		{q5}, [sp, :128]!
	vld1.8		{q9}, [sp, :128]!
	vld1.8		{q13}, [sp, :128]

	// 32-byte temporary space for _chacha_perm4
	sub		sp, #16

	// Permute the 4 blocks

	// Deinterleave 64-bit words in state n, n+2
	vswp		d1, d4		// (0 1 2 3) (0 1 2 3) => (0 1 0 1) (2 3 2 3)
	vswp		d3, d6		// (0 1 2 3) (0 1 2 3) => (0 1 0 1) (2 3 2 3)
	vswp		d9, d12
	vswp		d11, d14
	vswp		d17, d20
	vswp		d19, d22
	vswp		d25, d28
	vswp		d27, d30

	// Deinterleave 32-bit words in state n, n+1
	vuzp.32		q0, q1		// (0 1 0 1) (0 1 0 1) => (0 0 0 0) (1 1 1 1)
	vuzp.32		q2, q3		// (2 3 2 3) (2 3 2 3) => (2 2 2 2) (3 3 3 3)
	vuzp.32		q4, q5
	vuzp.32		q6, q7
	vuzp.32		q8, q9
	vuzp.32		q10, q11
	vuzp.32		q12, q13
	vuzp.32		q14, q15

.if \decrypting
	_chacha_invperm4
.else
#if USE_VTBL
	adr		ip, .Lrol8_table_memcrypt
	b		1f
	.align		3
.Lrol8_table_memcrypt:
	.byte		3, 0, 1, 2, 7, 4, 5, 6
1:
#endif
	_chacha_perm4

	vld1.32		{q8-q9}, [sp, :256]
.endif

	sub		sp, #32
	mov		ip, r0

	// Re-interleave 32-bit words in state n, n+1
	vzip.32		q0, q1
	vzip.32		q2, q3
	vzip.32		q4, q5
	vzip.32		q6, q7
	vzip.32		q8, q9
	vzip.32		q10, q11
	vzip.32		q12, q13
	vzip.32		q14, q15

	// Re-interleave 64-bit words in state n, n+2
	vswp		d1, d4
	vswp		d3, d6
	vswp		d9, d12
	vswp		d11, d14
	vswp		d17, d20
	vswp		d19, d22
	vswp		d25, d28
	vswp		d27, d30

	// Spill fourth block and reload 'mask'
	vst1.8		{q3}, [sp, :128]!
	vld1.8		{q3}, [ip]!
	vst1.8		{q7}, [sp, :128]!
	vld1.8		{q7}, [ip]!
	vst1.8		{q11}, [sp, :128]!
	vld1.8		{q11}, [ip]!
	vst1.8		{q15}, [sp, :128]!
	vld1.8		{q15}, [ip]

	// XOR first block with mask and save to 'dst'
	veor		q0, q3
	vst1.8		{q0}, [r1]!
	veor		q4, q7
	vst1.8		{q4}, [r1]!
	veor		q8, q11
	vst1.8		{q8}, [r1]!
	veor		q12, q15
	vst1.8		{q12}, [r1]!

	// Reload next mask words
	vld1.8		{q12}, [sp, :128]
	sub		sp, #64

	// XOR second block with mask and save to 'dst'
	_next_mask	q3, q7, q11, q15, q12
	veor		q0, q1, q3
	veor		q1, q5, q7
	vst1.8		{q0-q1}, [r1]!
	veor		q4, q9, q11
	veor		q5, q13, q15
	vst1.8		{q4-q5}, [r1]!

	// XOR third block with mask and save to 'dst'
	_next_mask	q3, q7, q11, q15, q12
	veor		q0, q2, q3
	veor		q1, q6, q7
	vst1.8		{q0-q1}, [r1]!
	veor		q4, q10, q11
	veor		q5, q14, q15
	vst1.8		{q4-q5}, [r1]!

	// Reload fourth block, XOR with mask, and save to 'dst'
	vld1.8		{q4-q5}, [sp, :256]!
	vld1.8		{q8-q9}, [sp, :256]
	_next_mask	q3, q7, q11, q15, q12
	veor		q4, q3
	veor		q5, q7
	vst1.8		{q4-q5}, [r1]!
	veor		q8, q11
	veor		q9, q15
	vst1.8		{q8-q9}, [r1]

	// Store new mask
	vext.8		q4, q3, q7, #4
	vext.8		q5, q7, q11, #4
	vst1.8		{q4-q5}, [r0]!
	vext.8		q6, q11, q15, #4
	vext.8		q7, q15, q12, #4
	vst1.8		{q6-q7}, [r0]

	mov		sp, r4
	pop		{r4}
	vldmia		sp!, {q4-q7}
	bx		lr
.endm

ENTRY(chacha_mem_encrypt_4block_neon)
	_chacha_mem_crypt_4block_neon	decrypting=0
ENDPROC(chacha_mem_encrypt_4block_neon)

ENTRY(chacha_mem_decrypt_4block_neon)
	_chacha_mem_crypt_4block_neon	decrypting=1
ENDPROC(chacha_mem_decrypt_4block_neon)
