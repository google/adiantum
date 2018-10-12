/* SPDX-License-Identifier: OpenSSL OR (BSD-3-Clause OR GPL-2.0)
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Modified by Eric Biggers, 2018 for HPolyC and Adiantum benchmarking where
 * Poly1305 is used for its ε-almost-∆-universal hash property, not as a MAC:
 *
 *  - Drop scalar code path, so the accumulator is always base 2^26.
 *    This simplifies the usage.
 *
 *  - Precompute key powers array in C code and pass it in separately.
 *    This is useful when the same key is used for many messages.
 *
 *  - Strip the state down to just the accumulator 'u32 h[5]'.
 *
 *  - Skip final addition of 'nonce' at end; the caller now handles it.
 */

#include "asm_common.h"

.text
#if defined(__thumb2__)
.syntax	unified
.thumb
#else
.code	32
#endif

.fpu	neon

.align	5
ENTRY(poly1305_blocks_neon)
	ands	r2,r2,#-16
	beq	.Lno_data_neon

	stmdb   sp!,{r4-r8}
	ldr	r8, [sp, #20]		@ key_powers
	vstmdb  sp!,{d8-d15}            @ ABI specification says so

.align	4
	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@ load hash value

	veor		d10,d10,d10
	veor		d12,d12,d12
	veor		d14,d14,d14
	veor		d16,d16,d16
	veor		d18,d18,d18
	vld4.32		{d10[0],d12[0],d14[0],d16[0]},[r0]!
	adr		r5,.Lzeros
	vld1.32		{d18[0]},[r0]
	sub		r0,r0,#16		@ rewind

	add		r4,r1,#32
	mov		r3,r3,lsl#24
	tst		r2,#31
	beq		.Leven

	vld4.32		{d20[0],d22[0],d24[0],d26[0]},[r1]!
	vmov.32		d28[0],r3
	sub		r2,r2,#16
	add		r4,r1,#32

#ifdef	__ARMEB__
	vrev32.8	q10,q10
	vrev32.8	q13,q13
	vrev32.8	q11,q11
	vrev32.8	q12,q12
#endif
	vsri.u32	d28,d26,#8	@ base 2^32 -> base 2^26
	vshl.u32	d26,d26,#18

	vsri.u32	d26,d24,#14
	vshl.u32	d24,d24,#12
	vadd.i32	d29,d28,d18	@ add hash value and move to #hi

	vbic.i32	d26,#0xfc000000
	vsri.u32	d24,d22,#20
	vshl.u32	d22,d22,#6

	vbic.i32	d24,#0xfc000000
	vsri.u32	d22,d20,#26
	vadd.i32	d27,d26,d16

	vbic.i32	d20,#0xfc000000
	vbic.i32	d22,#0xfc000000
	vadd.i32	d25,d24,d14

	vadd.i32	d21,d20,d10
	vadd.i32	d23,d22,d12

	mov		r7,r5
	mov		r6,r8

	cmp		r2,r2
	b		.Long_tail

.align	4
.Leven:
	subs		r2,r2,#64
	it		lo
	movlo		r4,r5

	vmov.i32	q14,#1<<24		@ padbit, yes, always
	vld4.32		{d20,d22,d24,d26},[r1]	@ inp[0:1]
	add		r1,r1,#64
	vld4.32		{d21,d23,d25,d27},[r4]	@ inp[2:3] (or 0)
	add		r4,r4,#64
	itt		hi
	addhi		r7,r8,#(1*9*4)
	addhi		r6,r8,#(3*9*4)

#ifdef	__ARMEB__
	vrev32.8	q10,q10
	vrev32.8	q13,q13
	vrev32.8	q11,q11
	vrev32.8	q12,q12
#endif
	vsri.u32	q14,q13,#8		@ base 2^32 -> base 2^26
	vshl.u32	q13,q13,#18

	vsri.u32	q13,q12,#14
	vshl.u32	q12,q12,#12

	vbic.i32	q13,#0xfc000000
	vsri.u32	q12,q11,#20
	vshl.u32	q11,q11,#6

	vbic.i32	q12,#0xfc000000
	vsri.u32	q11,q10,#26

	vbic.i32	q10,#0xfc000000
	vbic.i32	q11,#0xfc000000

	bls		.Lskip_loop

	vld4.32		{d0[1],d1[1],d2[1],d3[1]},[r7]!	@ load r^2
	vld4.32		{d0[0],d1[0],d2[0],d3[0]},[r6]!	@ load r^4
	vld4.32		{d4[1],d5[1],d6[1],d7[1]},[r7]!
	vld4.32		{d4[0],d5[0],d6[0],d7[0]},[r6]!
	b		.Loop_neon

.align	5
.Loop_neon:
	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@ ((inp[0]*r^4+inp[2]*r^2+inp[4])*r^4+inp[6]*r^2
	@ ((inp[1]*r^4+inp[3]*r^2+inp[5])*r^3+inp[7]*r
	@   ___________________/
	@ ((inp[0]*r^4+inp[2]*r^2+inp[4])*r^4+inp[6]*r^2+inp[8])*r^2
	@ ((inp[1]*r^4+inp[3]*r^2+inp[5])*r^4+inp[7]*r^2+inp[9])*r
	@   ___________________/ ____________________/
	@
	@ Note that we start with inp[2:3]*r^2. This is because it
	@ doesn't depend on reduction in previous iteration.
	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@ d4 = h4*r0 + h3*r1   + h2*r2   + h1*r3   + h0*r4
	@ d3 = h3*r0 + h2*r1   + h1*r2   + h0*r3   + h4*5*r4
	@ d2 = h2*r0 + h1*r1   + h0*r2   + h4*5*r3 + h3*5*r4
	@ d1 = h1*r0 + h0*r1   + h4*5*r2 + h3*5*r3 + h2*5*r4
	@ d0 = h0*r0 + h4*5*r1 + h3*5*r2 + h2*5*r3 + h1*5*r4

	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@ inp[2:3]*r^2

	vadd.i32	d24,d24,d14	@ accumulate inp[0:1]
	vmull.u32	q7,d25,d0[1]
	vadd.i32	d20,d20,d10
	vmull.u32	q5,d21,d0[1]
	vadd.i32	d26,d26,d16
	vmull.u32	q8,d27,d0[1]
	vmlal.u32	q7,d23,d1[1]
	vadd.i32	d22,d22,d12
	vmull.u32	q6,d23,d0[1]

	vadd.i32	d28,d28,d18
	vmull.u32	q9,d29,d0[1]
	subs		r2,r2,#64
	vmlal.u32	q5,d29,d2[1]
	it		lo
	movlo		r4,r5
	vmlal.u32	q8,d25,d1[1]
	vld1.32		d8[1],[r7,:32]
	vmlal.u32	q6,d21,d1[1]
	vmlal.u32	q9,d27,d1[1]

	vmlal.u32	q5,d27,d4[1]
	vmlal.u32	q8,d23,d3[1]
	vmlal.u32	q9,d25,d3[1]
	vmlal.u32	q6,d29,d4[1]
	vmlal.u32	q7,d21,d3[1]

	vmlal.u32	q8,d21,d5[1]
	vmlal.u32	q5,d25,d6[1]
	vmlal.u32	q9,d23,d5[1]
	vmlal.u32	q6,d27,d6[1]
	vmlal.u32	q7,d29,d6[1]

	vmlal.u32	q8,d29,d8[1]
	vmlal.u32	q5,d23,d8[1]
	vmlal.u32	q9,d21,d7[1]
	vmlal.u32	q6,d25,d8[1]
	vmlal.u32	q7,d27,d8[1]

	vld4.32		{d21,d23,d25,d27},[r4]	@ inp[2:3] (or 0)
	add		r4,r4,#64

	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@ (hash+inp[0:1])*r^4 and accumulate

	vmlal.u32	q8,d26,d0[0]
	vmlal.u32	q5,d20,d0[0]
	vmlal.u32	q9,d28,d0[0]
	vmlal.u32	q6,d22,d0[0]
	vmlal.u32	q7,d24,d0[0]
	vld1.32		d8[0],[r6,:32]

	vmlal.u32	q8,d24,d1[0]
	vmlal.u32	q5,d28,d2[0]
	vmlal.u32	q9,d26,d1[0]
	vmlal.u32	q6,d20,d1[0]
	vmlal.u32	q7,d22,d1[0]

	vmlal.u32	q8,d22,d3[0]
	vmlal.u32	q5,d26,d4[0]
	vmlal.u32	q9,d24,d3[0]
	vmlal.u32	q6,d28,d4[0]
	vmlal.u32	q7,d20,d3[0]

	vmlal.u32	q8,d20,d5[0]
	vmlal.u32	q5,d24,d6[0]
	vmlal.u32	q9,d22,d5[0]
	vmlal.u32	q6,d26,d6[0]
	vmlal.u32	q8,d28,d8[0]

	vmlal.u32	q7,d28,d6[0]
	vmlal.u32	q5,d22,d8[0]
	vmlal.u32	q9,d20,d7[0]
	vmov.i32	q14,#1<<24		@ padbit, yes, always
	vmlal.u32	q6,d24,d8[0]
	vmlal.u32	q7,d26,d8[0]

	vld4.32		{d20,d22,d24,d26},[r1]	@ inp[0:1]
	add		r1,r1,#64
#ifdef	__ARMEB__
	vrev32.8	q10,q10
	vrev32.8	q11,q11
	vrev32.8	q12,q12
	vrev32.8	q13,q13
#endif

	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@ lazy reduction interleaved with base 2^32 -> base 2^26 of
	@ inp[0:3] previously loaded to q10-q13 and smashed to q10-q14.

	vshr.u64	q15,q8,#26
	vmovn.i64	d16,q8
	 vshr.u64	q4,q5,#26
	 vmovn.i64	d10,q5
	vadd.i64	q9,q9,q15		@ h3 -> h4
	vbic.i32	d16,#0xfc000000
	  vsri.u32	q14,q13,#8		@ base 2^32 -> base 2^26
	 vadd.i64	q6,q6,q4		@ h0 -> h1
	  vshl.u32	q13,q13,#18
	 vbic.i32	d10,#0xfc000000

	vshrn.u64	d30,q9,#26
	vmovn.i64	d18,q9
	 vshr.u64	q4,q6,#26
	 vmovn.i64	d12,q6
	 vadd.i64	q7,q7,q4		@ h1 -> h2
	  vsri.u32	q13,q12,#14
	vbic.i32	d18,#0xfc000000
	  vshl.u32	q12,q12,#12
	 vbic.i32	d12,#0xfc000000

	vadd.i32	d10,d10,d30
	vshl.u32	d30,d30,#2
	  vbic.i32	q13,#0xfc000000
	 vshrn.u64	d8,q7,#26
	 vmovn.i64	d14,q7
	vaddl.u32	q5,d10,d30	@ h4 -> h0 [widen for a sec]
	  vsri.u32	q12,q11,#20
	 vadd.i32	d16,d16,d8	@ h2 -> h3
	  vshl.u32	q11,q11,#6
	 vbic.i32	d14,#0xfc000000
	  vbic.i32	q12,#0xfc000000

	vshrn.u64	d30,q5,#26		@ re-narrow
	vmovn.i64	d10,q5
	  vsri.u32	q11,q10,#26
	  vbic.i32	q10,#0xfc000000
	 vshr.u32	d8,d16,#26
	 vbic.i32	d16,#0xfc000000
	vbic.i32	d10,#0xfc000000
	vadd.i32	d12,d12,d30	@ h0 -> h1
	 vadd.i32	d18,d18,d8	@ h3 -> h4
	  vbic.i32	q11,#0xfc000000

	bhi		.Loop_neon

.Lskip_loop:
	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@ multiply (inp[0:1]+hash) or inp[2:3] by r^2:r^1

	add		r7,r8,#(0*9*4)
	add		r6,r8,#(1*9*4)
	adds		r2,r2,#32
	it		ne
	movne		r2,#0
	bne		.Long_tail

	vadd.i32	d25,d24,d14	@ add hash value and move to #hi
	vadd.i32	d21,d20,d10
	vadd.i32	d27,d26,d16
	vadd.i32	d23,d22,d12
	vadd.i32	d29,d28,d18

.Long_tail:
	vld4.32		{d0[1],d1[1],d2[1],d3[1]},[r7]!	@ load r^1
	vld4.32		{d0[0],d1[0],d2[0],d3[0]},[r6]!	@ load r^2

	vadd.i32	d24,d24,d14	@ can be redundant
	vmull.u32	q7,d25,d0
	vadd.i32	d20,d20,d10
	vmull.u32	q5,d21,d0
	vadd.i32	d26,d26,d16
	vmull.u32	q8,d27,d0
	vadd.i32	d22,d22,d12
	vmull.u32	q6,d23,d0
	vadd.i32	d28,d28,d18
	vmull.u32	q9,d29,d0

	vmlal.u32	q5,d29,d2
	vld4.32		{d4[1],d5[1],d6[1],d7[1]},[r7]!
	vmlal.u32	q8,d25,d1
	vld4.32		{d4[0],d5[0],d6[0],d7[0]},[r6]!
	vmlal.u32	q6,d21,d1
	vmlal.u32	q9,d27,d1
	vmlal.u32	q7,d23,d1

	vmlal.u32	q8,d23,d3
	vld1.32		d8[1],[r7,:32]
	vmlal.u32	q5,d27,d4
	vld1.32		d8[0],[r6,:32]
	vmlal.u32	q9,d25,d3
	vmlal.u32	q6,d29,d4
	vmlal.u32	q7,d21,d3

	vmlal.u32	q8,d21,d5
	 it		ne
	 addne		r7,r8,#(2*9*4)
	vmlal.u32	q5,d25,d6
	 it		ne
	 addne		r6,r8,#(3*9*4)
	vmlal.u32	q9,d23,d5
	vmlal.u32	q6,d27,d6
	vmlal.u32	q7,d29,d6

	vmlal.u32	q8,d29,d8
	 vorn		q0,q0,q0	@ all-ones, can be redundant
	vmlal.u32	q5,d23,d8
	 vshr.u64	q0,q0,#38
	vmlal.u32	q9,d21,d7
	vmlal.u32	q6,d25,d8
	vmlal.u32	q7,d27,d8

	beq		.Lshort_tail

	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@ (hash+inp[0:1])*r^4:r^3 and accumulate

	vld4.32		{d0[1],d1[1],d2[1],d3[1]},[r7]!	@ load r^3
	vld4.32		{d0[0],d1[0],d2[0],d3[0]},[r6]!	@ load r^4

	vmlal.u32	q7,d24,d0
	vmlal.u32	q5,d20,d0
	vmlal.u32	q8,d26,d0
	vmlal.u32	q6,d22,d0
	vmlal.u32	q9,d28,d0

	vmlal.u32	q5,d28,d2
	vld4.32		{d4[1],d5[1],d6[1],d7[1]},[r7]!
	vmlal.u32	q8,d24,d1
	vld4.32		{d4[0],d5[0],d6[0],d7[0]},[r6]!
	vmlal.u32	q6,d20,d1
	vmlal.u32	q9,d26,d1
	vmlal.u32	q7,d22,d1

	vmlal.u32	q8,d22,d3
	vld1.32		d8[1],[r7,:32]
	vmlal.u32	q5,d26,d4
	vld1.32		d8[0],[r6,:32]
	vmlal.u32	q9,d24,d3
	vmlal.u32	q6,d28,d4
	vmlal.u32	q7,d20,d3

	vmlal.u32	q8,d20,d5
	vmlal.u32	q5,d24,d6
	vmlal.u32	q9,d22,d5
	vmlal.u32	q6,d26,d6
	vmlal.u32	q7,d28,d6

	vmlal.u32	q8,d28,d8
	 vorn		q0,q0,q0	@ all-ones
	vmlal.u32	q5,d22,d8
	 vshr.u64	q0,q0,#38
	vmlal.u32	q9,d20,d7
	vmlal.u32	q6,d24,d8
	vmlal.u32	q7,d26,d8

.Lshort_tail:
	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@ horizontal addition

	vadd.i64	d16,d16,d17
	vadd.i64	d10,d10,d11
	vadd.i64	d18,d18,d19
	vadd.i64	d12,d12,d13
	vadd.i64	d14,d14,d15

	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@ lazy reduction, but without narrowing

	vshr.u64	q15,q8,#26
	vand.i64	q8,q8,q0
	 vshr.u64	q4,q5,#26
	 vand.i64	q5,q5,q0
	vadd.i64	q9,q9,q15		@ h3 -> h4
	 vadd.i64	q6,q6,q4		@ h0 -> h1

	vshr.u64	q15,q9,#26
	vand.i64	q9,q9,q0
	 vshr.u64	q4,q6,#26
	 vand.i64	q6,q6,q0
	 vadd.i64	q7,q7,q4		@ h1 -> h2

	vadd.i64	q5,q5,q15
	vshl.u64	q15,q15,#2
	 vshr.u64	q4,q7,#26
	 vand.i64	q7,q7,q0
	vadd.i64	q5,q5,q15		@ h4 -> h0
	 vadd.i64	q8,q8,q4		@ h2 -> h3

	vshr.u64	q15,q5,#26
	vand.i64	q5,q5,q0
	 vshr.u64	q4,q8,#26
	 vand.i64	q8,q8,q0
	vadd.i64	q6,q6,q15		@ h0 -> h1
	 vadd.i64	q9,q9,q4		@ h3 -> h4

	cmp		r2,#0
	bne		.Leven

	@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	@ store hash value

	vst4.32		{d10[0],d12[0],d14[0],d16[0]},[r0]!
	vst1.32		{d18[0]},[r0]

	vldmia	sp!,{d8-d15}			@ epilogue
	ldmia	sp!,{r4-r8}
.Lno_data_neon:
	bx	lr					@ bx	lr
ENDPROC(poly1305_blocks_neon)

.align	5
ENTRY(poly1305_emit_neon)

	stmdb	sp!,{r4-r11}

	ldmia	r0,{r3-r7}
	eor	r8,r8,r8

	adds	r3,r3,r4,lsl#26	@ base 2^26 -> base 2^32
	mov	r4,r4,lsr#6
	adcs	r4,r4,r5,lsl#20
	mov	r5,r5,lsr#12
	adcs	r5,r5,r6,lsl#14
	mov	r6,r6,lsr#18
	adcs	r6,r6,r7,lsl#8
	adc	r7,r8,r7,lsr#24	@ can be partially reduced ...

	and	r8,r7,#-4		@ ... so reduce
	and	r7,r6,#3
	add	r8,r8,r8,lsr#2	@ *= 5
	adds	r3,r3,r8
	adcs	r4,r4,#0
	adcs	r5,r5,#0
	adcs	r6,r6,#0
	adc	r7,r7,#0

	adds	r8,r3,#5		@ compare to modulus
	adcs	r9,r4,#0
	adcs	r10,r5,#0
	adcs	r11,r6,#0
	adc	r7,r7,#0
	tst	r7,#4			@ did it carry/borrow?

	it	ne
	movne	r3,r8
	it	ne
	movne	r4,r9
	it	ne
	movne	r5,r10
	it	ne
	movne	r6,r11

#ifdef __ARMEB__
	rev	r3,r3
	rev	r4,r4
	rev	r5,r5
	rev	r6,r6
#endif
	str	r3,[r1,#0]		@ store the result
	str	r4,[r1,#4]
	str	r5,[r1,#8]
	str	r6,[r1,#12]

	ldmia	sp!,{r4-r11}
	bx	lr				@ bx	lr
ENDPROC(poly1305_emit_neon)

.align	5
.Lzeros:
.long	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
