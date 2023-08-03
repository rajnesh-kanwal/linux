// SPDX-License-Identifier: GPL-2.0
/*
 * Control transfer records extension Helpers.
 *
 * Copyright (C) 2023 Rivos Inc.
 *
 * Author: Rajnesh Kanwal <rkanwal@rivosinc.com>
 */

#include "riscv_ctr.h"

static unsigned int get_nr_valid_ctr_entries(unsigned int depth)
{
	unsigned int status = csr_read(CSR_CTRSTATUS);

	if (status & CTRSTATUS_WRAP)
		return depth;

	return FIELD_GET(CTRSTATUS_WRPTR_MASK, status);
}

/* Reads ctr CSRs at index = idx and stores it in entry struct. */
static bool capture_ctr_regset(struct ctr_regset *entry, unsigned int idx)
{
	entry->src = get_ctr_src_reg(idx);

	if (!ctr_record_valid(entry->src))
		return false;

	entry->src = entry->src & (~CTRSOURCE_VALID);
	entry->target = get_ctr_tgt_reg(idx);
	entry->ctr_data = get_ctr_data_reg(idx);

    pr_err("%lx %lx %lx", entry->src, entry->target, entry->ctr_data);

	return true;
}

/* This function reads new available entries and append those to
 * saved entries array in ctx.
 *
 * To avoid moving entries around we save entries in oldest to newest
 * order. Lets say S0-S4 being the entries already present where S0
 * is newest and S4 is oldest.
 *
 * We then read new entries N0-N4, N0 being newest and N4 being oldest.
 * We will end-up with the given stored array.
 *
 * Idx    0  1  2  3  4  5  6  7  8  9
 * Entry S4 S3 S2 S1 S0 N4 N3 N2 N1 N0
 *
 * Inorder to save entries in the reverse order we will need to
 * shift old entries by the number of new entries, which is quite
 * costly.
 */
static int save_new_entries(struct riscv_perf_task_context *ctx,
			    unsigned int depth)
{
	struct ctr_regset *dst;
	unsigned int num_new_entries;
	unsigned int next;
	unsigned int i;
	u64 ctr_ctl;

	/* Depth should be a power of two. */
	WARN_ON_ONCE(depth & (depth - 1));

	ctr_ctl = csr_read_clear(CSR_CTRCONTROL, CTR_BRANCH_ENABLE_BITS);

	num_new_entries = get_nr_valid_ctr_entries(depth);

	next = num_new_entries - 1;

	for (i = 0; i < num_new_entries; i++) {
		dst = &ctx->store[ctx->head];

		if (!capture_ctr_regset(dst, next)) {
			break;
		}

		ctx->head = (ctx->head + 1) & (depth - 1);
		next--;
	}

	csr_set(CSR_CTRCONTROL, ctr_ctl & CTR_BRANCH_ENABLE_BITS);

	ctx->num_entries = min(ctx->num_entries + i, depth);

	return ctx->num_entries;
}

void riscv_pmu_ctr_save(struct riscv_pmu *riscv_pmu, void *ctx)
{
	struct riscv_perf_task_context *task_ctx = ctx;

	save_new_entries(task_ctx, riscv_pmu->ctr_depth);
	task_ctx->ctr_control = csr_read(CSR_CTRCONTROL);
	csr_write(CSR_CTRCONTROL, 0);
}

void riscv_pmu_ctr_restore(void *ctx)
{
	struct riscv_perf_task_context *task_ctx = ctx;

	csr_write(CSR_CTRCONTROL, task_ctx->ctr_control);
}

static uint64_t allowed_filters __read_mostly;

bool riscv_pmu_ctr_valid(struct perf_event *event)
{
	u64 branch_type = event->attr.branch_sample_type;

	if (branch_type & ~allowed_filters) {
		pr_err("Some of the requested branch filter are not supported 0x%llx\n",
		       branch_type & ~allowed_filters);
		return false;
	}

	return true;
}

static inline struct kmem_cache *
riscv_create_ctr_task_ctx_kmem_cache(size_t size)
{
	return kmem_cache_create("riscv_ctr_task_ctx", size, 0, 0, NULL);
}

void riscv_pmu_ctr_finish(struct riscv_pmu *riscv_pmu)
{
	if (!riscv_pmu_ctr_supported(riscv_pmu))
		return;

	riscv_pmu->ctr_depth = 0;

	kmem_cache_destroy(riscv_pmu->pmu.task_ctx_cache);
}

/* Generic perf branch filters supported by CTR extension. */
#define CTR_EXCLUDE_BRANCH_FILTERS (PERF_SAMPLE_BRANCH_ABORT_TX	        | \
				    PERF_SAMPLE_BRANCH_IN_TX		| \
				    PERF_SAMPLE_BRANCH_PRIV_SAVE        | \
				    PERF_SAMPLE_BRANCH_NO_TX)

#define CTR_ALLOWED_BRANCH_FILTERS (PERF_SAMPLE_BRANCH_USER		| \
				    PERF_SAMPLE_BRANCH_KERNEL		| \
				    PERF_SAMPLE_BRANCH_HV		| \
				    PERF_SAMPLE_BRANCH_ANY		| \
				    PERF_SAMPLE_BRANCH_ANY_CALL	        | \
				    PERF_SAMPLE_BRANCH_ANY_RETURN	| \
				    PERF_SAMPLE_BRANCH_IND_CALL	        | \
				    PERF_SAMPLE_BRANCH_COND		| \
				    PERF_SAMPLE_BRANCH_IND_JUMP	        | \
				    PERF_SAMPLE_BRANCH_HW_INDEX	        | \
				    PERF_SAMPLE_BRANCH_NO_FLAGS	        | \
				    PERF_SAMPLE_BRANCH_NO_CYCLES	| \
				    PERF_SAMPLE_BRANCH_CALL_STACK       | \
				    PERF_SAMPLE_BRANCH_CALL		| \
				    PERF_SAMPLE_BRANCH_TYPE_SAVE)

#define CTR_PERF_BRANCH_FILTERS    (CTR_ALLOWED_BRANCH_FILTERS	        | \
				    CTR_EXCLUDE_BRANCH_FILTERS)

/*
 * We check for hardware supported perf filters here. CTR hardware only
 * supports filters given in CTR_ALLOWED_BRANCH_FILTERS. To avoid missing
 * any new added filter in perf, we do a BUILD_BUG_ON check, so make sure
 * to update CTR_ALLOWED_BRANCH_FILTERS or CTR_EXCLUDE_BRANCH_FILTERS
 * defines when adding support for it in below function.
 */
static void check_available_filters(void)
{
	uint64_t ctr_ctl;

	/*
	 * Ensure both perf branch filter allowed and exclude
	 * masks are always in sync with the generic perf ABI.
	 */
	BUILD_BUG_ON(CTR_PERF_BRANCH_FILTERS != (PERF_SAMPLE_BRANCH_MAX - 1));

	allowed_filters = PERF_SAMPLE_BRANCH_USER      |
			  PERF_SAMPLE_BRANCH_KERNEL    |
			  PERF_SAMPLE_BRANCH_ANY       |
			  PERF_SAMPLE_BRANCH_HW_INDEX  |
			  PERF_SAMPLE_BRANCH_NO_FLAGS  |
			  PERF_SAMPLE_BRANCH_NO_CYCLES |
			  PERF_SAMPLE_BRANCH_TYPE_SAVE;

	csr_write(CSR_CTRCONTROL, ~0);
	ctr_ctl = csr_read(CSR_CTRCONTROL);

	if (riscv_isa_extension_available(NULL, h))
		allowed_filters |= PERF_SAMPLE_BRANCH_HV;

	if (ctr_ctl & (CTRCONTROL_INDCALL_INH | CTRCONTROL_DIRCALL_INH))
		allowed_filters |= PERF_SAMPLE_BRANCH_ANY_CALL;

	if (ctr_ctl & (CTRCONTROL_RET_INH | CTRCONTROL_TRETINH))
		allowed_filters |= PERF_SAMPLE_BRANCH_ANY_RETURN;

	if (ctr_ctl & CTRCONTROL_INDCALL_INH)
		allowed_filters |= PERF_SAMPLE_BRANCH_IND_CALL;

	if (ctr_ctl & CTRCONTROL_TKBRINH)
		allowed_filters |= PERF_SAMPLE_BRANCH_COND;

	if (ctr_ctl & CTRCONTROL_RASEMU)
		allowed_filters |= PERF_SAMPLE_BRANCH_CALL_STACK;

	if (ctr_ctl & (CTRCONTROL_INDOJUMP_INH | CTRCONTROL_INDJUMP_INH))
		allowed_filters |= PERF_SAMPLE_BRANCH_IND_JUMP;

	if (ctr_ctl & CTRCONTROL_DIRCALL_INH)
		allowed_filters |= PERF_SAMPLE_BRANCH_CALL;
}

int riscv_pmu_ctr_init(struct riscv_pmu *riscv_pmu)
{
	size_t size = sizeof(struct riscv_perf_task_context);

	if (!riscv_isa_extension_available(NULL, SxCTR) ||
	    !riscv_isa_extension_available(NULL, SSCOFPMF) ||
	    !riscv_isa_extension_available(NULL, SxCSRIND))
		return 0;

	riscv_pmu->pmu.task_ctx_cache =
		riscv_create_ctr_task_ctx_kmem_cache(size);
	if (!riscv_pmu->pmu.task_ctx_cache)
		return -ENOMEM;

	check_available_filters();

	csr_write(CSR_CTRCONTROL, CTRCONTROL_DEPTH_MASK);
	riscv_pmu->ctr_depth = ctr_get_depth(csr_read(CSR_CTRCONTROL));

	pr_info("Perf CTR available\n");

	return 0;
}

/* TODO: branches are optional, check at runtime. */
static u64 branch_type_to_ctr(int branch_type)
{
	u64 config = CTR_BRANCH_FILTERS_INH | CTRCONTROL_LCOFIFRZ |
		     CTRCONTROL_DEPTH_MASK;

	if (branch_type & PERF_SAMPLE_BRANCH_USER)
		config |= CTRCONTROL_U_ENABLE;

	if (branch_type & PERF_SAMPLE_BRANCH_KERNEL)
		config |= CTRCONTROL_KERNEL_ENABLE;

	if (branch_type & PERF_SAMPLE_BRANCH_HV) {
		if (riscv_isa_extension_available(NULL, h))
			config |= CTRCONTROL_KERNEL_ENABLE;
	}

	if (branch_type & PERF_SAMPLE_BRANCH_ANY) {
		config &= ~CTR_BRANCH_FILTERS_INH;
		return config;
	}

	if (branch_type & PERF_SAMPLE_BRANCH_ANY_CALL) {
		config &= ~CTRCONTROL_INDCALL_INH;
		config &= ~CTRCONTROL_DIRCALL_INH;
		config &= ~CTRCONTROL_EXCINH;
		config &= ~CTRCONTROL_INTRINH;
	}

	if (branch_type & PERF_SAMPLE_BRANCH_ANY_RETURN)
		config &= ~(CTRCONTROL_RET_INH | CTRCONTROL_TRETINH);

	if (branch_type & PERF_SAMPLE_BRANCH_IND_CALL)
		config &= ~CTRCONTROL_INDCALL_INH;

	if (branch_type & PERF_SAMPLE_BRANCH_COND)
		config &= ~CTRCONTROL_TKBRINH;

	if (branch_type & PERF_SAMPLE_BRANCH_CALL_STACK) {
		config &= ~(CTRCONTROL_INDCALL_INH | CTRCONTROL_DIRCALL_INH |
			    CTRCONTROL_RET_INH);
		config |= CTRCONTROL_RASEMU;
	}

	if (branch_type & PERF_SAMPLE_BRANCH_IND_JUMP) {
		config &= ~CTRCONTROL_INDJUMP_INH;
		config &= ~CTRCONTROL_INDOJUMP_INH;
	}

	if (branch_type & PERF_SAMPLE_BRANCH_CALL)
		config &= ~CTRCONTROL_DIRCALL_INH;

	return config;
}

void riscv_pmu_ctr_enable(struct perf_event *event)
{
	struct riscv_perf_task_context *task_ctx =
		event->pmu_ctx->task_ctx_data;
	u64 branch_type = event->attr.branch_sample_type;
	u64 ctr;

	ctr = branch_type_to_ctr(branch_type);
	csr_write(CSR_CTRCONTROL, ctr);

	if (event->ctx->task) {
		task_ctx->head = 0;
		task_ctx->num_entries = 0;
	}

	riscv_pmu_ctr_reset();
}

void riscv_pmu_ctr_disable(struct perf_event *event)
{
	/* Clear the CTRCONTROL to disable the recording. We keep frozen
	 * bit intact. Frozen must only be reset by IRQ handler.
	 */
	csr_clear(CSR_CTRCONTROL, 0);
}

static const int ctr_perf_map[] = {
	[CTRDATA_TYPE_NONE]			= PERF_BR_UNKNOWN,
	[CTRDATA_TYPE_EXCEPTION]		= PERF_BR_SYSCALL,
	[CTRDATA_TYPE_INTERRUPT]		= PERF_BR_IRQ,
	[CTRDATA_TYPE_TRAP_RET]			= PERF_BR_ERET,
	[CTRDATA_TYPE_NONTAKEN_BRANCH]  	= PERF_BR_COND,
	[CTRDATA_TYPE_TAKEN_BRANCH]		= PERF_BR_COND,
	[CTRDATA_TYPE_EXTERNAL_TRAP]		= PERF_BR_UNKNOWN,
	[CTRDATA_TYPE_RESERVED]			= PERF_BR_UNKNOWN,
	[CTRDATA_TYPE_INDIRECT_CALL]		= PERF_BR_IND_CALL,
	[CTRDATA_TYPE_DIRECT_CALL]		= PERF_BR_CALL,
	[CTRDATA_TYPE_INDIRECT_JUMP]		= PERF_BR_UNCOND,
	[CTRDATA_TYPE_DIRECT_JUMP]		= PERF_BR_UNKNOWN,
	[CTRDATA_TYPE_CO_ROUTINE_SWAP]		= PERF_BR_UNKNOWN,
	[CTRDATA_TYPE_RETURN]			= PERF_BR_RET,
	[CTRDATA_TYPE_OTHER_INDIRECT_JUMP]	= PERF_BR_IND,
	[CTRDATA_TYPE_OTHER_DIRECT_JUMP]	= PERF_BR_UNKNOWN,
};

static void ctr_set_perf_entry_type(struct perf_branch_entry *entry,
				    u64 ctr_data)
{
	int ctr_type = ctr_get_type(ctr_data);

	entry->type = ctr_perf_map[ctr_type];
	if (entry->type == PERF_BR_UNKNOWN)
		pr_warn("%d - unknown branch type captured\n", ctr_type);
}

static void capture_ctr_flags(struct perf_branch_entry *entry,
			      struct perf_event *event, u64 ctr_data,
			      u64 ctr_target)
{
	if (branch_sample_type(event))
		ctr_set_perf_entry_type(entry, ctr_data);

	if (!branch_sample_no_cycles(event))
		entry->cycles = ctr_get_cycles(ctr_data);

	if (!branch_sample_no_flags(event)) {
		entry->abort = 0;
		entry->mispred = ctr_get_mispredict(ctr_target);
		entry->predicted = !entry->mispred;
	}

	if (branch_sample_priv(event))
		entry->priv = PERF_BR_PRIV_UNKNOWN;
}

void riscv_pmu_ctr_reset(void)
{
	csr_set(CSR_CTRCONTROL, CTRCONTROL_CLR);
}

static void ctr_regset_to_branch_entry(struct cpu_hw_events *cpuc,
				       struct perf_event *event,
				       struct ctr_regset *regset,
				       unsigned int idx)
{
	struct perf_branch_entry *entry = &cpuc->branches->branch_entries[idx];

	perf_clear_branch_entry_bitfields(entry);
	entry->from = regset->src;
	entry->to = regset->target & (~CTRTARGET_MISP);
	capture_ctr_flags(entry, event, regset->ctr_data, regset->target);
}

static void process_saved_ctr_entries(struct cpu_hw_events *cpuc,
				      struct perf_event *event,
				      struct riscv_perf_task_context *ctx,
				      unsigned int depth)
{
	struct ctr_regset *stored = ctx->store;
	int store_idx = (ctx->head - 1) & (depth - 1);
	int i;

	WARN_ON_ONCE(depth & (depth - 1));

	for (i = 0; i < ctx->num_entries; i++) {
		ctr_regset_to_branch_entry(cpuc, event, &stored[store_idx], i);
		store_idx = (store_idx - 1) & (depth - 1);
	}

	cpuc->branches->branch_stack.nr = ctx->num_entries;
	cpuc->branches->branch_stack.hw_idx = 0;
}

static void process_new_ctr_entries(struct cpu_hw_events *cpuc,
				    struct perf_event *event,
				    unsigned int depth)
{
	struct ctr_regset entry;
	u64 ctr_ctl;
	int i;

	WARN_ON_ONCE(depth & (depth - 1));

	ctr_ctl = csr_read_clear(CSR_CTRCONTROL, CTR_BRANCH_ENABLE_BITS);

	for (i = 0; i < MAX_BRANCH_RECORDS; i++) {
		if (capture_ctr_regset(&entry, i))
			break;

		ctr_regset_to_branch_entry(cpuc, event, &entry, i);
	}

	csr_set(CSR_CTRCONTROL, ctr_ctl & CTR_BRANCH_ENABLE_BITS);

	cpuc->branches->branch_stack.nr = i;
	cpuc->branches->branch_stack.hw_idx = 0;
}

void riscv_pmu_ctr_read(struct cpu_hw_events *cpuc, struct perf_event *event)
{
	struct riscv_perf_task_context *task_ctx =
		event->pmu_ctx->task_ctx_data;

	if (event->ctx->task) {
		save_new_entries(task_ctx, cpuc->pmu->ctr_depth);
		process_saved_ctr_entries(cpuc, event, task_ctx,
					  cpuc->pmu->ctr_depth);
		task_ctx->num_entries = 0;
	} else {
		process_new_ctr_entries(cpuc, event, cpuc->pmu->ctr_depth);
	}

	/* Unfreeze the buffer */
	csr_clear(CSR_CTRSTATUS, CTRSTATUS_FROZEN);
	riscv_pmu_ctr_reset();
}
