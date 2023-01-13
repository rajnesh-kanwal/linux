// SPDX-License-Identifier: GPL-2.0
/*
 * TEE SBI extension related header file.
 *
 * Copyright (c) 2023 Rivos Inc.
 *
 * Authors:
 *     Rajnesh Kanwal <rkanwal@rivosinc.com>
 */

#ifndef __RISCV_TEEG_SBI_H__
#define __RISCV_TEEG_SBI_H__

#ifdef CONFIG_RISCV_TRUSTED_VM

int sbi_teeg_add_mmio_region(unsigned long addr, unsigned long len);
int sbi_teeg_remove_mmio_region(unsigned long addr, unsigned long len);
int sbi_teeg_share_memory(unsigned long addr, unsigned long len);
int sbi_teeg_unshare_memory(unsigned long addr, unsigned long len);
int sbi_teeg_allow_external_interrupt(unsigned long id);
int sbi_teeg_allow_all_external_interrupt(void);
int sbi_teeg_deny_external_interrupt(unsigned long id);
int sbi_teeg_deny_all_external_interrupt(void);

#else

static inline int sbi_teeg_add_mmio_region(unsigned long addr, unsigned long len) {return 0;}
static inline int sbi_teeg_remove_mmio_region(unsigned long addr, unsigned long len) {return 0;}
static inline int sbi_teeg_share_memory(unsigned long addr, unsigned long len) {return 0;}
static inline int sbi_teeg_unshare_memory(unsigned long addr, unsigned long len) {return 0;}
static inline int sbi_teeg_allow_external_interrupt(unsigned long id) {return 0;}
static inline int sbi_teeg_allow_all_external_interrupt(void) {return 0;}
static inline int sbi_teeg_deny_external_interrupt(unsigned long id) {return 0;}
static inline int sbi_teeg_deny_all_external_interrupt(void) {return 0;}

#endif

#endif /* __RISCV_TEEG_SBI_H__ */
