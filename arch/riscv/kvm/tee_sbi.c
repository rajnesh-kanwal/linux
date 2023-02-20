// SPDX-License-Identifier: GPL-2.0
/*
 * TEE SBI extensions related helper functions.
 *
 * Copyright (c) 2022 RivosInc
 *
 * Authors:
 *     Atish Patra <atishp@rivosinc.com>
 */

#include <linux/align.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <asm/csr.h>
#include <asm/kvm_tee_sbi.h>
#include <asm/sbi.h>

int sbi_teei_tvm_aia_init(unsigned long tvm_gid,
			  struct sbi_tee_tvm_aia_params *tvm_aia_params)
{
	struct sbiret ret;

	unsigned long pa = __pa(tvm_aia_params);

	ret = sbi_ecall(SBI_EXT_TEEI, SBI_EXT_TEEI_TVM_AIA_INIT, tvm_gid, pa,
			sizeof(*tvm_aia_params), 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teei_set_vcpu_imsic_addr(unsigned long tvm_gid, unsigned long vcpu_id,
				 unsigned long imsic_addr)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEI, SBI_EXT_TEEI_TVM_CPU_SET_IMSIC_ADDR,
			tvm_gid, vcpu_id, imsic_addr, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

/*
 * Converts the guest interrupt file at `imsic_addr` for use with a TVM.
 * The guest interrupt file must not be used by the caller until reclaim.
 */
int sbi_teei_convert_imsic(unsigned long imsic_addr)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEI, SBI_EXT_TEEI_TVM_CONVERT_IMSIC,
			imsic_addr, 0, 0, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teei_reclaim_imsic(unsigned long imsic_addr)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEI, SBI_EXT_TEEI_TVM_RECLAIM_IMSIC,
			imsic_addr, 0, 0, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

/*
 * Binds a vCPU to this physical CPU and the specified set of confidential guest
 * interrupt files.
 */
int sbi_teei_bind_vcpu_imsic(unsigned long tvm_gid, unsigned long vcpu_id,
			     unsigned long imsic_mask)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEI, SBI_EXT_TEEI_TVM_CPU_BIND_IMSIC, tvm_gid,
			vcpu_id, imsic_mask, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

/*
 * Begins the unbind process for the specified vCPU from this physical CPU and its guest
 * interrupt files. The host must complete a TLB invalidation sequence for the TVM before
 * completing the unbind with `unbind_vcpu_imsic_end()`.
 */
int sbi_teei_unbind_vcpu_imsic_begin(unsigned long tvm_gid,
				     unsigned long vcpu_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEI, SBI_EXT_TEEI_TVM_CPU_UNBIND_IMSIC_BEGIN,
			tvm_gid, vcpu_id, 0, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

/*
 * Completes the unbind process for the specified vCPU from this physical CPU and its guest
 * interrupt files.
 */
int sbi_teei_unbind_vcpu_imsic_end(unsigned long tvm_gid, unsigned long vcpu_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEI, SBI_EXT_TEEI_TVM_CPU_UNBIND_IMSIC_END,
			tvm_gid, vcpu_id, 0, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

/*
 * Injects an external interrupt into the specified vCPU. The interrupt ID must
 * have been allowed with `allow_external_interrupt()` by the guest.
 */
int sbi_teei_inject_external_interrupt(unsigned long tvm_gid,
				       unsigned long vcpu_id,
				       unsigned long interrupt_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEI, SBI_EXT_TEEI_TVM_CPU_INJECT_EXT_INTERRUPT,
			tvm_gid, vcpu_id, interrupt_id, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teei_rebind_vcpu_imsic_begin(unsigned long tvm_gid,
				     unsigned long vcpu_id,
				     unsigned long imsic_mask)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEI, SBI_EXT_TEEI_TVM_REBIND_IMSIC_BEGIN,
			tvm_gid, vcpu_id, imsic_mask, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teei_rebind_vcpu_imsic_clone(unsigned long tvm_gid,
				     unsigned long vcpu_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEI, SBI_EXT_TEEI_TVM_REBIND_IMSIC_CLONE,
			tvm_gid, vcpu_id, 0, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teei_rebind_vcpu_imsic_end(unsigned long tvm_gid, unsigned long vcpu_id)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEI, SBI_EXT_TEEI_TVM_REBIND_IMSIC_END,
			tvm_gid, vcpu_id, 0, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teeh_tsm_get_info(struct sbi_tee_tsm_info *tinfo_addr)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TSM_GET_INFO, __pa(tinfo_addr),
			sizeof(*tinfo_addr), 0, 0, 0, 0);

	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teeh_tvm_initiate_fence(unsigned long tvmid)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TVM_INITIATE_FENCE, tvmid, 0, 0, 0, 0, 0);

	//TODO: handle already progress call
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;

}

int sbi_teeh_tsm_global_fence(void)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TSM_INITIATE_FENCE, 0, 0, 0, 0, 0, 0);

	//TODO: handle already progress call
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teeh_tsm_local_fence(void)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TSM_LOCAL_FENCE, 0, 0, 0, 0, 0, 0);

	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teeh_tsm_create_tvm(struct sbi_tee_tvm_create_params *tparam, unsigned long *tvmid)
{
	struct sbiret ret;
	int rc = 0;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_CREATE_TVM, __pa(tparam),
			sizeof(*tparam), 0, 0, 0, 0);

	if (ret.error) {
		rc = sbi_err_map_linux_errno(ret.error);
		if (rc == -EFAULT)
			kvm_err("Invalid phsyical address for tvm params structure\n");
		goto done;
	}

	*tvmid = ret.value;
done:
	return rc;
}

int sbi_teeh_tsm_finalize_tvm(unsigned long tvmid, unsigned long sepc, unsigned long entry_arg)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_FINALIZE_TVM, tvmid,
			sepc, entry_arg, 0, 0, 0);

	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teeh_tsm_destroy_tvm(unsigned long tvmid)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_DESTROY_TVM, tvmid,
			0, 0, 0, 0, 0);

	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

#define RISCV_TEE_ALIGN_4KB (1UL << 12)

int sbi_teeh_add_memory_region(unsigned long tvmid, enum sbi_tee_mem_type mtype,
			       unsigned long tgpaddr, unsigned long rlen)
{
	struct sbiret ret;

	if (!IS_ALIGNED(tgpaddr, RISCV_TEE_ALIGN_4KB) || !IS_ALIGNED(rlen, RISCV_TEE_ALIGN_4KB))
		return -EINVAL;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TVM_ADD_MEMORY_REGION, tvmid, tgpaddr, rlen, 0, 0, 0);
	if (ret.error) {
		kvm_err("Add memory region failed with sbi error code %ld\n", ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	return 0;
}

int sbi_teeh_tsm_convert_pages(unsigned long phys_addr, unsigned long npages)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TSM_CONVERT_PAGES, phys_addr,
			npages, 0, 0, 0, 0);
	if (ret.error) {
		kvm_err("%s: In failed ret %ld\n", __func__, ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}
	return 0;
}

int sbi_teeh_tsm_reclaim_page(unsigned long page_addr_phys)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TSM_RECLAIM_PAGES, page_addr_phys,
			1, 0, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teeh_tsm_reclaim_pages(unsigned long phys_addr, unsigned long npages)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TSM_RECLAIM_PAGES, phys_addr,
			npages, 0, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teeh_add_pgt_pages(unsigned long tvmid, unsigned long page_addr_phys, unsigned long npages)
{
	struct sbiret ret;

	if (!PAGE_ALIGNED(page_addr_phys))
		return -EINVAL;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TVM_ADD_PGT_PAGES, tvmid, page_addr_phys,
			npages, 0, 0, 0);
	if (ret.error) {
		kvm_err("%s: In failed ret %ld\n", __func__, ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	return 0;
}

int sbi_teeh_add_measured_pages(unsigned long tvmid, unsigned long src_addr, unsigned long dest_addr,
				enum sbi_tee_page_type ptype,
			        unsigned long npages, unsigned long tgpa)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TVM_ADD_MEASURED_PAGES, tvmid, src_addr,
			dest_addr, ptype, npages, tgpa);
	if (ret.error) {
		kvm_err("%s: In failed ret %ld\n", __func__, ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	return 0;
}

int sbi_teeh_add_zero_pages(unsigned long tvmid, unsigned long page_addr_phys,
			    enum sbi_tee_page_type ptype,unsigned long npages,
			    unsigned long tvm_base_page_addr)
{
	struct sbiret ret;

	if (!PAGE_ALIGNED(page_addr_phys))
		return -EINVAL;
	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TVM_ADD_ZERO_PAGES, tvmid, page_addr_phys,
			ptype, npages, tvm_base_page_addr, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teeh_add_shared_pages(unsigned long tvmid, unsigned long page_addr_phys,
			      enum sbi_tee_page_type ptype,
			      unsigned long npages,
			      unsigned long tvm_base_page_addr)
{
	struct sbiret ret;

	if (!PAGE_ALIGNED(page_addr_phys))
		return -EINVAL;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TVM_ADD_SHARED_PAGES, tvmid,
			page_addr_phys, ptype, npages, tvm_base_page_addr, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	return 0;
}

int sbi_teeh_create_tvm_vcpu(unsigned long tvmid, unsigned long vcpuid,
			     unsigned long vcpu_state_paddr)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TVM_CREATE_VCPU, tvmid, vcpuid, vcpu_state_paddr, 0, 0, 0);
	if (ret.error) {
		kvm_err("%s: create vcpu failed ret %ld\n", __func__, ret.error);
		return sbi_err_map_linux_errno(ret.error);

	}
	return 0;
}

int sbi_teeh_run_tvm_vcpu(unsigned long tvmid, unsigned long vcpuid,
			  bool *is_blocked)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_TEEH, SBI_EXT_TEEH_TVM_VCPU_RUN, tvmid, vcpuid,
			0, 0, 0, 0);
	if (ret.error)
		return sbi_err_map_linux_errno(ret.error);

	*is_blocked = !!ret.value;

	return 0;
}
