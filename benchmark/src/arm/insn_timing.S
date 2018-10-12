/*
 * Benchmark ARM NEON instruction sequences
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "../asm_common.h"

	.text
	.fpu		neon

.macro _do_8_veor
	veor			q8,  q0
	veor			q9,  q1
	veor			q10, q2
	veor			q11, q3
	veor			q12, q4
	veor			q13, q5
	veor			q14, q6
	veor			q15, q7
.endm

ENTRY(arm_test_veor)
1:
	_do_8_veor
	_do_8_veor
	_do_8_veor
	_do_8_veor

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_veor_dep
	veor		q0, q0
	veor		q0, q0
	veor		q0, q0
	veor		q0, q0
	veor		q0, q0
	veor		q0, q0
	veor		q0, q0
	veor		q0, q0
.endm

ENTRY(arm_test_veor_dep)
	push	{r4-r8}
1:
	_do_8_veor_dep
	_do_8_veor_dep
	_do_8_veor_dep
	_do_8_veor_dep

	subs			r0, #1
	bne			1b
	pop	{r4-r8}
	bx			lr

.macro _do_8_vadd
	vadd.i32		q8,  q0
	vadd.i32		q9,  q1
	vadd.i32		q10, q2
	vadd.i32		q11, q3
	vadd.i32		q12, q4
	vadd.i32		q13, q5
	vadd.i32		q14, q6
	vadd.i32		q15, q7
.endm

ENTRY(arm_test_vadd)
1:
	_do_8_vadd
	_do_8_vadd
	_do_8_vadd
	_do_8_vadd

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vadd_dep
	vadd.u32	q0, q0
	vadd.u32	q0, q0
	vadd.u32	q0, q0
	vadd.u32	q0, q0
	vadd.u32	q0, q0
	vadd.u32	q0, q0
	vadd.u32	q0, q0
	vadd.u32	q0, q0
.endm

ENTRY(arm_test_vadd_dep)
	push	{r4-r8}
1:
	_do_8_vadd_dep
	_do_8_vadd_dep
	_do_8_vadd_dep
	_do_8_vadd_dep

	subs			r0, #1
	bne			1b
	pop	{r4-r8}
	bx			lr

.macro _do_8_vadd_veor
	vadd.i32		q8,  q0
	veor			q9,  q1
	vadd.i32		q10, q2
	veor			q11, q3
	vadd.i32		q12, q4
	veor			q13, q5
	vadd.i32		q14, q6
	veor			q15, q7
.endm

ENTRY(arm_test_vadd_veor)
1:
	_do_8_vadd_veor
	_do_8_vadd_veor
	_do_8_vadd_veor
	_do_8_vadd_veor

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vshl
	vshl.u32		q8,  q0, #8
	vshl.u32		q9,  q1, #8
	vshl.u32		q10, q2, #8
	vshl.u32		q11, q3, #8
	vshl.u32		q12, q4, #8
	vshl.u32		q13, q5, #8
	vshl.u32		q14, q6, #8
	vshl.u32		q15, q7, #8
.endm

ENTRY(arm_test_vshl)
1:
	_do_8_vshl
	_do_8_vshl
	_do_8_vshl
	_do_8_vshl

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vshl_dep
	vshl.u32		q0, q0, #8
	vshl.u32		q0, q0, #8
	vshl.u32		q0, q0, #8
	vshl.u32		q0, q0, #8
	vshl.u32		q0, q0, #8
	vshl.u32		q0, q0, #8
	vshl.u32		q0, q0, #8
	vshl.u32		q0, q0, #8
.endm

ENTRY(arm_test_vshl_dep)
1:
	_do_8_vshl_dep
	_do_8_vshl_dep
	_do_8_vshl_dep
	_do_8_vshl_dep

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vshr
	vshr.u32		q8,  q0, #8
	vshr.u32		q9,  q1, #8
	vshr.u32		q10, q2, #8
	vshr.u32		q11, q3, #8
	vshr.u32		q12, q4, #8
	vshr.u32		q13, q5, #8
	vshr.u32		q14, q6, #8
	vshr.u32		q15, q7, #8
.endm

ENTRY(arm_test_vshr)
1:
	_do_8_vshr
	_do_8_vshr
	_do_8_vshr
	_do_8_vshr

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vrev
	vrev32.16	q0, q0
	vrev32.16	q1, q1
	vrev32.16	q2, q2
	vrev32.16	q3, q3
	vrev32.16	q4, q4
	vrev32.16	q5, q5
	vrev32.16	q6, q6
	vrev32.16	q7, q7
.endm

ENTRY(arm_test_vrev)
1:
	_do_8_vrev
	_do_8_vrev
	_do_8_vrev
	_do_8_vrev

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vrev_dep
	vrev32.16	q0, q0
	vrev32.16	q0, q0
	vrev32.16	q0, q0
	vrev32.16	q0, q0
	vrev32.16	q0, q0
	vrev32.16	q0, q0
	vrev32.16	q0, q0
	vrev32.16	q0, q0
.endm

ENTRY(arm_test_vrev_dep)
1:
	_do_8_vrev_dep
	_do_8_vrev_dep
	_do_8_vrev_dep
	_do_8_vrev_dep

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vsri
	vsri.u32		q8,  q0, #8
	vsri.u32		q9,  q1, #8
	vsri.u32		q10, q2, #8
	vsri.u32		q11, q3, #8
	vsri.u32		q12, q4, #8
	vsri.u32		q13, q5, #8
	vsri.u32		q14, q6, #8
	vsri.u32		q15, q7, #8
.endm

ENTRY(arm_test_vsri)
1:
	_do_8_vsri
	_do_8_vsri
	_do_8_vsri
	_do_8_vsri

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vsri_dep
	vsri.u32		q0, q0, #8
	vsri.u32		q0, q0, #8
	vsri.u32		q0, q0, #8
	vsri.u32		q0, q0, #8
	vsri.u32		q0, q0, #8
	vsri.u32		q0, q0, #8
	vsri.u32		q0, q0, #8
	vsri.u32		q0, q0, #8
.endm

ENTRY(arm_test_vsri_dep)
1:
	_do_8_vsri_dep
	_do_8_vsri_dep
	_do_8_vsri_dep
	_do_8_vsri_dep

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vshl_veor
	vshl.u32		q8,  q0, #8
	veor			q9,  q1
	vshl.u32		q10, q2, #8
	veor			q11, q3
	vshl.u32		q12, q4, #8
	veor			q13, q5
	vshl.u32		q14, q6, #8
	veor			q15, q7
.endm

ENTRY(arm_test_vshl_veor)
1:
	_do_8_vshl_veor
	_do_8_vshl_veor
	_do_8_vshl_veor
	_do_8_vshl_veor

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vshl_vsri
	vshl.u32		q4,  q0, #8
	vshl.u32		q5,  q1, #8
	vshl.u32		q6,  q2, #8
	vshl.u32		q7,  q3, #8
	vsri.u32		q4,  q0, #24
	vsri.u32		q5,  q1, #24
	vsri.u32		q6,  q2, #24
	vsri.u32		q7,  q3, #24
	vshl.u32		q4,  q0, #8
	vshl.u32		q5,  q1, #8
	vshl.u32		q6,  q2, #8
	vshl.u32		q7,  q3, #8
	vsri.u32		q4,  q0, #24
	vsri.u32		q5,  q1, #24
	vsri.u32		q6,  q2, #24
	vsri.u32		q7,  q3, #24
.endm

ENTRY(arm_test_vshl_vsri)
1:
	_do_8_vshl_vsri
	_do_8_vshl_vsri
	_do_8_vshl_vsri
	_do_8_vshl_vsri

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vshl_vshr_vorr
	vshl.u32		q4,  q0, #8
	vshl.u32		q5,  q1, #8
	vshl.u32		q6,  q2, #8
	vshl.u32		q7,  q3, #8
	vshr.u32		q0, #24
	vshr.u32		q1, #24
	vshr.u32		q2, #24
	vshr.u32		q3, #24
	vorr			q4, q0
	vorr			q5, q0
	vorr			q6, q0
	vorr			q7, q0
	vshl.u32		q4,  q0, #8
	vshl.u32		q5,  q1, #8
	vshl.u32		q6,  q2, #8
	vshl.u32		q7,  q3, #8
	vshr.u32		q0, #24
	vshr.u32		q1, #24
	vshr.u32		q2, #24
	vshr.u32		q3, #24
	vorr			q4, q0
	vorr			q5, q0
	vorr			q6, q0
	vorr			q7, q0
.endm

ENTRY(arm_test_vshl_vshr_vorr)
1:
	_do_8_vshl_vshr_vorr
	_do_8_vshl_vshr_vorr
	_do_8_vshl_vshr_vorr
	_do_8_vshl_vshr_vorr

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vshl_vshr_veor
	vshl.u32		q4,  q0, #8
	vshl.u32		q5,  q1, #8
	vshl.u32		q6,  q2, #8
	vshl.u32		q7,  q3, #8
	vshr.u32		q0, #24
	vshr.u32		q1, #24
	vshr.u32		q2, #24
	vshr.u32		q3, #24
	veor			q4, q0
	veor			q5, q0
	veor			q6, q0
	veor			q7, q0
	vshl.u32		q4,  q0, #8
	vshl.u32		q5,  q1, #8
	vshl.u32		q6,  q2, #8
	vshl.u32		q7,  q3, #8
	vshr.u32		q0, #24
	vshr.u32		q1, #24
	vshr.u32		q2, #24
	vshr.u32		q3, #24
	veor			q4, q0
	veor			q5, q0
	veor			q6, q0
	veor			q7, q0
.endm

ENTRY(arm_test_vshl_vshr_veor)
1:
	_do_8_vshl_vshr_veor
	_do_8_vshl_vshr_veor
	_do_8_vshl_vshr_veor
	_do_8_vshl_vshr_veor

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vtbl
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
	vtbl.8		d2, {d2}, d31
	vtbl.8		d3, {d3}, d31
	vtbl.8		d4, {d4}, d31
	vtbl.8		d5, {d5}, d31
	vtbl.8		d6, {d6}, d31
	vtbl.8		d7, {d7}, d31
	vtbl.8		d8, {d8}, d31
	vtbl.8		d9, {d9}, d31
	vtbl.8		d10, {d10}, d31
	vtbl.8		d11, {d11}, d31
	vtbl.8		d12, {d12}, d31
	vtbl.8		d13, {d13}, d31
	vtbl.8		d14, {d14}, d31
	vtbl.8		d15, {d15}, d31
.endm

ENTRY(arm_test_vtbl)
	adr		r12, .Lror32_8_table
	vld1.8		{d31}, [r12]
	b 1f
.Lror32_8_table:
	.byte		1, 2, 3, 0, 5, 6, 7, 4
1:
	_do_8_vtbl
	_do_8_vtbl
	_do_8_vtbl
	_do_8_vtbl

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vtbl_dep
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
.endm

ENTRY(arm_test_vtbl_dep)
	adr		r12, .Lror32_8_table_vtbl_dep
	vld1.8		{d31}, [r12]
	b 1f
.Lror32_8_table_vtbl_dep:
	.byte		1, 2, 3, 0, 5, 6, 7, 4
1:
	_do_8_vtbl_dep
	_do_8_vtbl_dep
	_do_8_vtbl_dep
	_do_8_vtbl_dep

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vtbl_veor
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
	veor		q7, q1
	vtbl.8		d4, {d4}, d31
	vtbl.8		d5, {d5}, d31
	veor		q11, q3
	vtbl.8		d8, {d8}, d31
	vtbl.8		d9, {d9}, d31
	veor		q13, q5
	vtbl.8		d12, {d12}, d31
	vtbl.8		d13, {d13}, d31
	veor		q13, q7
.endm

ENTRY(arm_test_vtbl_veor)
	adr		r12, .Lror32_8_table_vtbl_veor
	vld1.8		{d31}, [r12]
	b 1f
.Lror32_8_table_vtbl_veor:
	.byte		1, 2, 3, 0, 5, 6, 7, 4
1:
	_do_8_vtbl_veor
	_do_8_vtbl_veor
	_do_8_vtbl_veor
	_do_8_vtbl_veor

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vtbl_vadd
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
	vadd.u32	q7, q1
	vtbl.8		d4, {d4}, d31
	vtbl.8		d5, {d5}, d31
	vadd.u32	q11, q3
	vtbl.8		d8, {d8}, d31
	vtbl.8		d9, {d9}, d31
	vadd.u32	q13, q5
	vtbl.8		d12, {d12}, d31
	vtbl.8		d13, {d13}, d31
	vadd.u32	q13, q7
.endm

ENTRY(arm_test_vtbl_vadd)
	adr		r12, .Lror32_8_table_vtbl_vadd
	vld1.8		{d31}, [r12]
	b 1f
.Lror32_8_table_vtbl_vadd:
	.byte		1, 2, 3, 0, 5, 6, 7, 4
1:
	_do_8_vtbl_vadd
	_do_8_vtbl_vadd
	_do_8_vtbl_vadd
	_do_8_vtbl_vadd

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vtbl_vshl
	vtbl.8		d0, {d0}, d31
	vtbl.8		d1, {d1}, d31
	vshl.u32	q7, q1, #31
	vtbl.8		d4, {d4}, d31
	vtbl.8		d5, {d5}, d31
	vshl.u32	q11, q3, #31
	vtbl.8		d8, {d8}, d31
	vtbl.8		d9, {d9}, d31
	vshl.u32	q13, q5, #31
	vtbl.8		d12, {d12}, d31
	vtbl.8		d13, {d13}, d31
	vshl.u32	q14, q7, #31
.endm

ENTRY(arm_test_vtbl_vshl)
	adr		r12, .Lror32_8_table_vtbl_vshl
	vld1.8		{d31}, [r12]
	b 1f
.Lror32_8_table_vtbl_vshl:
	.byte		1, 2, 3, 0, 5, 6, 7, 4
1:
	_do_8_vtbl_vshl
	_do_8_vtbl_vshl
	_do_8_vtbl_vshl
	_do_8_vtbl_vshl

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vrev_vadd
	vrev32.16	q0, q0
	vadd.u32	q7, q1
	vrev32.16	q2, q2
	vadd.u32	q11, q3
	vrev32.16	q4, q4
	vadd.u32	q13, q5
	vrev32.16	q6, q6
	vadd.u32	q15, q7
.endm

ENTRY(arm_test_vrev_vadd)
1:
	_do_8_vrev_vadd
	_do_8_vrev_vadd
	_do_8_vrev_vadd
	_do_8_vrev_vadd

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_vrev_veor
	vrev32.16	q0, q0
	veor		q7, q1
	vrev32.16	q2, q2
	veor		q11, q3
	vrev32.16	q4, q4
	veor		q13, q5
	vrev32.16	q6, q6
	veor		q15, q7
.endm

ENTRY(arm_test_vrev_veor)
1:
	_do_8_vrev_veor
	_do_8_vrev_veor
	_do_8_vrev_veor
	_do_8_vrev_veor

	subs			r0, #1
	bne			1b
	bx			lr

.macro _do_8_add
	add		r1, r12
	add		r2, r12
	add		r3, r12
	add		r4, r12
	add		r5, r12
	add		r6, r12
	add		r7, r12
	add		r8, r12
.endm

ENTRY(arm_test_add)
	push	{r4-r8}
1:
	_do_8_add
	_do_8_add
	_do_8_add
	_do_8_add

	subs			r0, #1
	bne			1b
	pop	{r4-r8}
	bx			lr

.macro _do_8_vadd_add
	vadd.u32	q8, q0
	add		r1, r12
	vadd.u32	q9, q1
	add		r2, r12
	vadd.u32	q10, q2
	add		r3, r12
	vadd.u32	q11, q3
	add		r4, r12
	vadd.u32	q12, q4
	add		r5, r12
	vadd.u32	q13, q5
	add		r6, r12
	vadd.u32	q14, q6
	add		r7, r12
	vadd.u32	q15, q7
	add		r8, r12
.endm

ENTRY(arm_test_vadd_add)
	push	{r4-r8}
1:
	_do_8_vadd_add
	_do_8_vadd_add
	_do_8_vadd_add
	_do_8_vadd_add

	subs			r0, #1
	bne			1b
	pop	{r4-r8}
	bx			lr

.macro _do_8_eor
	eor		r1, r12
	eor		r2, r12
	eor		r3, r12
	eor		r4, r12
	eor		r5, r12
	eor		r6, r12
	eor		r7, r12
	eor		r8, r12
.endm

ENTRY(arm_test_eor)
	push	{r4-r8}
1:
	_do_8_eor
	_do_8_eor
	_do_8_eor
	_do_8_eor

	subs			r0, #1
	bne			1b
	pop	{r4-r8}
	bx			lr

.macro _do_8_veor_eor
	veor		q8, q0
	eor		r1, r12
	veor		q9, q1
	eor		r2, r12
	veor		q10, q2
	eor		r3, r12
	veor		q11, q3
	eor		r4, r12
	veor		q12, q4
	eor		r5, r12
	veor		q13, q5
	eor		r6, r12
	veor		q14, q6
	eor		r7, r12
	veor		q15, q7
	eor		r8, r12
.endm

ENTRY(arm_test_veor_eor)
	push	{r4-r8}
1:
	_do_8_veor_eor
	_do_8_veor_eor
	_do_8_veor_eor
	_do_8_veor_eor

	subs			r0, #1
	bne			1b
	pop	{r4-r8}
	bx			lr

.macro _do_8_veor_add
	veor		q8, q0
	add		r1, r12
	veor		q9, q1
	add		r2, r12
	veor		q10, q2
	add		r3, r12
	veor		q11, q3
	add		r4, r12
	veor		q12, q4
	add		r5, r12
	veor		q13, q5
	add		r6, r12
	veor		q14, q6
	add		r7, r12
	veor		q15, q7
	add		r8, r12
.endm

ENTRY(arm_test_veor_add)
	push	{r4-r8}
1:
	_do_8_veor_add
	_do_8_veor_add
	_do_8_veor_add
	_do_8_veor_add

	subs			r0, #1
	bne			1b
	pop	{r4-r8}
	bx			lr

.macro _do_16_vext
	vext.8	q0, q0, q0, #4
	vext.8	q1, q1, q1, #4
	vext.8	q2, q2, q2, #8
	vext.8	q3, q3, q3, #8
	vext.8	q4, q4, q4, #12
	vext.8	q5, q5, q5, #12
	vext.8	q6, q6, q6, #4
	vext.8	q7, q7, q7, #4

	vext.8	q8, q8, q8, #4
	vext.8	q9, q9, q9, #4
	vext.8	q10, q10, q10, #8
	vext.8	q11, q11, q11, #8
	vext.8	q12, q12, q12, #4
	vext.8	q13, q13, q13, #4
	vext.8	q14, q14, q14, #4
	vext.8	q15, q15, q15, #4
.endm

ENTRY(arm_test_vext)
1:
	_do_16_vext
	_do_16_vext
	_do_16_vext
	_do_16_vext

	subs			r0, #2
	bne			1b
	bx			lr

.macro _do_16_vext_vadd
	vext.8	q0, q0, q0, #4
	vadd.u32 q1, q1
	vext.8	q2, q2, q2, #4
	vadd.u32 q3, q3
	vext.8	q4, q4, q4, #4
	vadd.u32 q5, q5
	vext.8	q6, q6, q6, #4
	vadd.u32 q7, q7

	vext.8	q8, q8, q8, #4
	vadd.u32 q9, q9
	vext.8	q10, q10, q10, #4
	vadd.u32 q11, q11
	vext.8	q12, q12, q12, #4
	vadd.u32 q13, q13
	vext.8	q14, q14, q14, #4
	vadd.u32 q15, q15
.endm

ENTRY(arm_test_vext_vadd)
1:
	_do_16_vext_vadd
	_do_16_vext_vadd
	_do_16_vext_vadd
	_do_16_vext_vadd

	subs			r0, #2
	bne			1b
	bx			lr

.macro _do_8_ror
	ror	r1, #31
	ror	r2, #31
	ror	r3, #31
	ror	r4, #31
	ror	r5, #31
	ror	r6, #31
	ror	r7, #31
	ror	r8, #31
.endm

ENTRY(arm_test_ror)
	push	{r4-r8}
1:
	_do_8_ror
	_do_8_ror
	_do_8_ror
	_do_8_ror

	subs			r0, #1
	bne			1b
	pop	{r4-r8}
	bx			lr

.macro _do_8_ror_vshl
	ror	r1, #31
	vshl.u32	q0, q0, #31
	ror	r2, #31
	vshl.u32	q1, q1, #31
	ror	r3, #31
	vshl.u32	q2, q2, #31
	ror	r4, #31
	vshl.u32	q3, q3, #31
	ror	r5, #31
	vshl.u32	q4, q4, #31
	ror	r6, #31
	vshl.u32	q5, q5, #31
	ror	r7, #31
	vshl.u32	q6, q6, #31
	ror	r8, #31
	vshl.u32	q7, q7, #31
.endm

ENTRY(arm_test_ror_vshl)
	push	{r4-r8}
1:
	_do_8_ror_vshl
	_do_8_ror_vshl
	_do_8_ror_vshl
	_do_8_ror_vshl

	subs			r0, #1
	bne			1b
	pop	{r4-r8}
	bx			lr


.macro _do_8_add_eor_rot
	add	r1, r1, r1, ROR #24
	eor	r2, r2, r2, ROR #24

	add	r1, r1, r1, ROR #24
	eor	r2, r2, r2, ROR #24

	add	r1, r1, r1, ROR #24
	eor	r2, r2, r2, ROR #24

	add	r1, r1, r1, ROR #24
	eor	r2, r2, r2, ROR #24

	add	r1, r1, r1, ROR #24
	eor	r2, r2, r2, ROR #24

	add	r1, r1, r1, ROR #24
	eor	r2, r2, r2, ROR #24

	add	r1, r1, r1, ROR #24
	eor	r2, r2, r2, ROR #24

	add	r1, r1, r1, ROR #24
	eor	r2, r2, r2, ROR #24
.endm

ENTRY(arm_test_add_eor_rot)
	push	{r4-r8}
1:
	_do_8_add_eor_rot
	_do_8_add_eor_rot
	_do_8_add_eor_rot
	_do_8_add_eor_rot

	subs			r0, #1
	bne			1b
	pop	{r4-r8}
	bx			lr

.macro _do_16_vzip_vswp
	vzip.32	q0, q1		// (0 1 0 1) (0 1 0 1)
	vzip.32	q2, q3		// (2 3 2 3) (2 3 2 3)
	vzip.32	q4, q5		// (4 5 4 5) (4 5 4 5)
	vzip.32	q6, q7		// (6 7 6 7) (6 7 6 7)
	vzip.32	q8, q9		// (8 9 8 9) (8 9 8 9)
	vzip.32	q10, q11	// (10 11 10 11) (10 11 10 11)
	vzip.32	q12, q13	// (12 13 12 13) (12 13 12 13)
	vzip.32	q14, q15	// (14 15 14 15) (14 15 14 15)
	vswp		d1, d4
	vswp		d3, d6
	vswp		d9, d12
	vswp		d11, d14
	vswp		d17, d20
	vswp		d19, d22
	vswp		d25, d28
	vswp		d27, d30
.endm

ENTRY(arm_test_vzip_vswp)
1:
	_do_16_vzip_vswp
	_do_16_vzip_vswp
	_do_16_vzip_vswp
	_do_16_vzip_vswp

	subs			r0, #2
	bne			1b
	bx			lr

.macro _do_16_vuzp
	vuzp.32		q0, q1		// (0 0 1 1) (0 0 1 1)
	vuzp.32		q2, q3		// (2 2 3 3) (2 2 3 3)
	vuzp.32		q4, q5		// (4 4 5 5) (4 4 5 5)
	vuzp.32		q6, q7		// (6 6 7 7) (6 6 7 7)
	vuzp.32		q8, q9		// (8 8 9 9) (8 8 9 9)
	vuzp.32		q10, q11	// (10 10 11 11) (10 10 11 11)
	vuzp.32		q12, q13	// (12 12 13 13) (12 12 13 13)
	vuzp.32		q14, q15	// (14 14 15 15) (14 14 15 15)

	vuzp.32		q0, q2		// (0 1 2 3) (0 1 2 3)
	vuzp.32		q1, q3		// (0 1 2 3) (0 1 2 3)
	vuzp.32		q4, q6		// (4 5 6 7) (4 5 6 7)
	vuzp.32		q5, q7		// (4 5 6 7) (4 5 6 7)
	vuzp.32		q8, q10		// (8 9 10 11) (8 9 10 11)
	vuzp.32		q9, q11		// (8 9 10 11) (8 9 10 11)
	vuzp.32		q12, q14	// (12 13 14 15) (12 13 14 15)
	vuzp.32		q13, q15	// (12 13 14 15) (12 13 14 15)
.endm

ENTRY(arm_test_vuzp)
1:
	_do_16_vuzp
	_do_16_vuzp
	_do_16_vuzp
	_do_16_vuzp

	subs			r0, #2
	bne			1b
	bx			lr
