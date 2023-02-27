/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TEE related header file.
 *
 * Copyright (c) 2023 RivosInc
 *
 * Authors:
 *     Atish Patra <atishp@rivosinc.com>
 */

#ifndef __KVM_RISCV_TEE_H
#define __KVM_RISCV_TEE_H

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/list.h>
#include <asm/csr.h>
#include <asm/sbi.h>

#define KVM_TEE_PAGE_SIZE_4K	(_AC(1,UL) << 12)
#define KVM_TEE_PAGE_SIZE_2MB	(_AC(1,UL) << 21)
#define KVM_TEE_PAGE_SIZE_1GB	(_AC(1,UL) << 30)
#define KVM_TEE_PAGE_SIZE_512GB (_AC(1,UL) << 39)

#define bytes_to_pages(n) ((n + PAGE_SIZE - 1) >> PAGE_SHIFT)

/* Allocate 2MB(i.e. 512 pages) for the page table pool */
#define KVM_TEE_PGTABLE_SIZE_MAX ((_AC(1,UL) << 10) * PAGE_SIZE)

#define get_order_num_pages(n) (get_order(n << PAGE_SHIFT))

/* This is part of UABI. DO NOT CHANGE IT */
struct kvm_riscv_tee_measure_region {
	/* Address of the user space where the VM code/data resides */
	unsigned long userspace_addr;

	/* The guest physical address where VM code/data should be mapped */
	unsigned long gpa;

	/* Size of the region */
	unsigned long size;
};

/* Describe a confidential or shared memory region */
struct kvm_riscv_tee_mem_region {
	unsigned long hva;
	unsigned long gpa;
	unsigned long npages;
};

/* Page management structure for the host */
struct kvm_riscv_tee_page {
	struct list_head link;

	/* Pointer to page allocated */
	struct page *page;

	/* number of pages allocated for page */
	unsigned long npages;

	/* Described the page type */
	unsigned long ptype;

	/* set if the page is mapped in guest physical address */
	bool is_mapped;

	/* The below two fileds are only valid if is_mapped is true */
	/* host virtual address for the mapping */
	unsigned long hva;
	/* guest physical address for the mapping */
	unsigned long gpa;
};

struct kvm_tee_tvm_vcpu_context {
	struct kvm_vcpu *vcpu;
	/* Pages storing each vcpu state of the TVM in TSM */
	struct kvm_riscv_tee_page vcpu_state;
};

struct kvm_tee_tvm_context {
	struct kvm *kvm;

	/* TODO: This is not really a VMID as TSM returns the page owner ID instead of VMID */
	unsigned long tvm_guest_id;

	/* Pages where TVM page table is stored */
	struct kvm_riscv_tee_page pgtable;

	/* Pages storing the TVM state in TSM */
	struct kvm_riscv_tee_page tvm_state;

	/* Keep track of zero pages */
	struct list_head zero_pages;

	/* Pages where TVM image is measured & loaded */
	struct list_head measured_pages;

	/* keep track of shared pages */
	struct list_head shared_pages;

	/* keep track of pending reclaim confidential pages */
	struct list_head reclaim_pending_pages;

	struct kvm_riscv_tee_mem_region shared_region;
	struct kvm_riscv_tee_mem_region confidential_region;

	bool finalized_done;
};

static inline bool is_tee_vm(struct kvm *kvm)
{
	return kvm->arch.vm_type == KVM_VM_TYPE_RISCV_TEE;
}

static inline bool is_tee_vcpu(struct kvm_vcpu *vcpu)
{
	return is_tee_vm(vcpu->kvm);
}

#ifdef CONFIG_RISCV_TEE_VM

bool kvm_riscv_tee_enabled(void);
int kvm_riscv_tee_init(void);

/* TVM related functions */
void kvm_riscv_tee_vm_destroy(struct kvm *kvm);
int kvm_riscv_tee_vm_init(struct kvm *kvm);

/* TVM VCPU related functions */
void kvm_riscv_tee_vcpu_destroy(struct kvm_vcpu *vcpu);
int kvm_riscv_tee_vcpu_init(struct kvm_vcpu *vcpu);
void kvm_riscv_tee_vcpu_load(struct kvm_vcpu *vcpu);
void kvm_riscv_tee_vcpu_put(struct kvm_vcpu *vcpu);
void kvm_riscv_tee_vcpu_switchto(struct kvm_vcpu *vcpu, struct kvm_cpu_trap *trap);

int kvm_riscv_tee_vm_measure_pages(struct kvm *kvm, struct kvm_riscv_tee_measure_region *mr);
int kvm_riscv_tee_vm_add_memreg(struct kvm *kvm, unsigned long gpa, unsigned long size);
int kvm_riscv_tee_gstage_map(struct kvm_vcpu *vcpu, gpa_t gpa, unsigned long hva);
#else
static inline bool kvm_riscv_tee_enabled(void) {return false ;};
static inline int kvm_riscv_tee_init(void) { return -1;}
static inline void kvm_riscv_tee_hardware_disable(void) {}
static inline int kvm_riscv_tee_hardware_enable(void) {return 0;}

/* TVM related functions */
static inline void kvm_riscv_tee_vm_destroy(struct kvm *kvm) {}
static inline int kvm_riscv_tee_vm_init(struct kvm *kvm) {return -1;}

/* TVM VCPU related functions */
static inline void kvm_riscv_tee_vcpu_destroy(struct kvm_vcpu *vcpu) {}
static inline int kvm_riscv_tee_vcpu_init(struct kvm_vcpu *vcpu) {return -1;}
static inline void kvm_riscv_tee_vcpu_load(struct kvm_vcpu *vcpu) {}
static inline void kvm_riscv_tee_vcpu_put(struct kvm_vcpu *vcpu) {}
static inline void kvm_riscv_tee_vcpu_switchto(struct kvm_vcpu *vcpu, struct kvm_cpu_trap *trap) {}
static inline int kvm_riscv_tee_vm_add_memreg(struct kvm *kvm, unsigned long gpa, unsigned long size) {return -1;}
static inline int kvm_riscv_tee_vm_measure_pages(struct kvm *kvm, struct kvm_riscv_tee_measure_region *mr) {return -1;}
static inline int kvm_riscv_tee_gstage_map(struct kvm_vcpu *vcpu,
					   gpa_t gpa, unsigned long hva) {return -1;}
#endif /* CONFIG_RISCV_TEE_VM */

#endif /* __KVM_RISCV_TEE_H */
