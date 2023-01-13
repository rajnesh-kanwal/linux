// SPDX-License-Identifier: GPL-2.0
/*
 * TVM helper functions
 *
 * Copyright (c) 2023 Rivos Inc.
 *
 * Authors:
 *     Rajnesh Kanwal <rkanwal@rivosinc.com>
 */

#ifndef __RISCV_TVM_H__
#define __RISCV_TVM_H__

#ifdef CONFIG_RISCV_TRUSTED_VM
void riscv_cc_sbi_init(void);
bool is_secure_guest(void);
#else /* CONFIG_RISCV_TEE_VM */
static inline bool is_secure_guest(void)
{
	return false;
}
static inline void riscv_cc_sbi_init(void)
{
}
#endif /* CONFIG_RISCV_TRUSTED_VM */

#endif /* __RISCV_TVM_H__ */
