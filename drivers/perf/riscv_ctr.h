/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Control transfer records extension Helpers.
 *
 * Copyright (C) 2023 Rivos Inc.
 *
 * Author: Rajnesh Kanwal <rkanwal@rivosinc.com>
 */
#define pr_fmt(fmt) "ctr: " fmt

#include <linux/perf/riscv_pmu.h>
#include <linux/bitfield.h>

#define CTR_BRANCH_FILTERS_INH  (CTRCONTROL_EXCINH |\
                             	 CTRCONTROL_INTRINH |\
                             	 CTRCONTROL_TRETINH |\
                             	 CTRCONTROL_BRINH |\
                             	 CTRCONTROL_INDCALL_INH |\
                             	 CTRCONTROL_DIRCALL_INH |\
                             	 CTRCONTROL_INDJUMP_INH |\
                             	 CTRCONTROL_DIRJUMP_INH |\
                             	 CTRCONTROL_CORSWAP_INH |\
                             	 CTRCONTROL_RET_INH |\
                             	 CTRCONTROL_INDOJUMP_INH |\
                             	 CTRCONTROL_DIROJUMP_INH)

#define CTR_BRANCH_ENABLE_BITS  (CTRCONTROL_KERNEL_ENABLE | CTRCONTROL_U_ENABLE)

#define CTR_MAX_ENTRIES 256

struct ctr_regset {
	unsigned long src;
	unsigned long target;
	unsigned long ctr_data;
};

struct ctr_hw_attr {
    unsigned depth;
};

/* Head is the idx of the next available slot. The slot may be already populated
 * by an old entry which will be lost on new writes.
 */
struct riscv_perf_task_context {
	struct ctr_regset store[CTR_MAX_ENTRIES];
	unsigned num_entries;
	unsigned head;
	uint64_t ctr_control
};

static inline u64 get_ctr_src_reg(unsigned ctr_idx)
{
	csr_write(CSR_ISELECT, CTR_ENTRIES_FIRST + ctr_idx);
    return csr_read(CSR_IREG);
}

static inline u64 get_ctr_tgt_reg(unsigned ctr_idx)
{
	csr_write(CSR_ISELECT, CTR_ENTRIES_FIRST + ctr_idx);
    return csr_read(CSR_IREG2);
}

static inline u64 get_ctr_data_reg(unsigned ctr_idx)
{
	csr_write(CSR_ISELECT, CTR_ENTRIES_FIRST + ctr_idx);
    return csr_read(CSR_IREG3);
}

static inline bool ctr_record_valid(u64 ctr_src)
{
	return !!FIELD_GET(CTRSOURCE_VALID, ctr_src);
}

static inline int ctr_get_mispredict(u64 ctr_target)
{
	return FIELD_GET(CTRTARGET_MISP, ctr_target);
}

static inline unsigned ctr_get_cycles(u64 ctr_data)
{
    const unsigned cce = FIELD_GET(CTRDATA_CCE_MASK, ctr_data);
    const unsigned ccm = FIELD_GET(CTRDATA_CCM_MASK, ctr_data);

	if (ctr_data & CTRDATA_CCV)
		return 0;

	if (cce > 0)
		return (4096 + ccm) << (cce - 1);

	return FIELD_GET(CTRDATA_CCM_MASK, ctr_data);
}

static inline int ctr_get_type(u64 ctr_data)
{
	return FIELD_GET(CTRDATA_TYPE_MASK, ctr_data);
}

static inline int ctr_get_depth(u64 ctr_control)
{
	/* Depth table from CTR Spec: 2.1 mctrcontrol.
	 * 
	 * ctrcontrol.depth       Depth
	 * 0000 				- 16
	 * 0001 				- 32
	 * 0011 				- 64
	 * 0111 				- 128
	 * 1111 				- 256
	 *
	 * Depth = (ctrcontrol.depth + 1) * 16 OR
	 * Depth = (ctrcontrol.depth + 1) << 4.
	 */
	return (FIELD_GET(CTRCONTROL_DEPTH_MASK, ctr_control) + 1) << 4;
}
