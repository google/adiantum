/*
 * Benchmark instruction sequences
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "util.h"

#ifdef __arm__
void arm_test_veor(u32 niter);
void arm_test_veor_dep(u32 niter);
void arm_test_vadd(u32 niter);
void arm_test_vadd_dep(u32 niter);
void arm_test_vadd_veor(u32 niter);
void arm_test_vshl(u32 niter);
void arm_test_vshl_dep(u32 niter);
void arm_test_vshr(u32 niter);
void arm_test_vrev(u32 niter);
void arm_test_vrev_dep(u32 niter);
void arm_test_vsri(u32 niter);
void arm_test_vsri_dep(u32 niter);
void arm_test_vshl_veor(u32 niter);
void arm_test_vshl_vsri(u32 niter);
void arm_test_vshl_vshr_vorr(u32 niter);
void arm_test_vshl_vshr_veor(u32 niter);
void arm_test_vtbl(u32 niter);
void arm_test_vtbl_dep(u32 niter);
void arm_test_vtbl_veor(u32 niter);
void arm_test_vtbl_vadd(u32 niter);
void arm_test_vtbl_vshl(u32 niter);
void arm_test_vrev_vadd(u32 niter);
void arm_test_vrev_veor(u32 niter);
void arm_test_add(u32 niter);
void arm_test_vadd_add(u32 niter);
void arm_test_eor(u32 niter);
void arm_test_veor_eor(u32 niter);
void arm_test_veor_add(u32 niter);
void arm_test_vext(u32 niter);
void arm_test_vext_vadd(u32 niter);
void arm_test_ror(u32 niter);
void arm_test_ror_vshl(u32 niter);
void arm_test_add_eor_rot(u32 niter);
void arm_test_vzip_vswp(u32 niter);
void arm_test_vuzp(u32 niter);

static void insn_test(const char *name, void (*func)(u32 niter))
{
	const u32 niter = 16384;
	const u64 ninsns = (u64)niter * 32;
	u64 t;

	t = now();
	func(niter);
	t = now() - t;

	printf("%-20s %6.2f\n", name, cycles_per_byte(ninsns, t));
	fflush(stdout);
}

void do_insn_timing(void)
{
	insn_test("veor", arm_test_veor);
	insn_test("veor(dep)", arm_test_veor_dep);
	insn_test("vadd", arm_test_vadd);
	insn_test("vadd(dep)", arm_test_vadd_dep);
	insn_test("vadd+veor", arm_test_vadd_veor);
	insn_test("vshl", arm_test_vshl);
	insn_test("vshl(dep)", arm_test_vshl_dep);
	insn_test("vshr", arm_test_vshr);
	insn_test("vrev", arm_test_vrev);
	insn_test("vrev(dep)", arm_test_vrev_dep);
	insn_test("vsri", arm_test_vsri);
	insn_test("vsri(dep)", arm_test_vsri_dep);
	insn_test("vshl+veor", arm_test_vshl_veor);
	insn_test("vshl+vsri", arm_test_vshl_vsri);
	insn_test("vshl+vshr+vorr", arm_test_vshl_vshr_vorr);
	insn_test("vshl+vshr+veor", arm_test_vshl_vshr_veor);
	insn_test("vtbl", arm_test_vtbl);
	insn_test("vtbl(dep)", arm_test_vtbl_dep);
	insn_test("vtbl+veor", arm_test_vtbl_veor);
	insn_test("vtbl+vadd", arm_test_vtbl_vadd);
	insn_test("vtbl+vshl", arm_test_vtbl_vshl);
	insn_test("vrev+vadd", arm_test_vrev_vadd);
	insn_test("vrev+veor", arm_test_vrev_veor);
	insn_test("add", arm_test_add);
	insn_test("vadd+add", arm_test_vadd_add);
	insn_test("eor", arm_test_add);
	insn_test("veor+eor", arm_test_veor_eor);
	insn_test("veor+add", arm_test_veor_add);
	insn_test("vext", arm_test_vext);
	insn_test("vext_vadd", arm_test_vext_vadd);
	insn_test("ror", arm_test_ror);
	insn_test("ror_vshl", arm_test_ror_vshl);
	insn_test("add_eor(rot)", arm_test_add_eor_rot);
	insn_test("vzip+vswp", arm_test_vzip_vswp);
	insn_test("vuzp", arm_test_vuzp);
}
#else /* __arm__ */
void do_insn_timing(void)
{
	printf("Instruction timing not implemented on this platform.\n");
}
#endif /* !__arm__ */
