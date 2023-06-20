/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 SiFive
 * Copyright (C) 2018 Andes Technology Corporation
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 *
 */

#ifndef _ASM_RISCV_PERF_EVENT_H
#define _ASM_RISCV_PERF_EVENT_H

#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/interrupt.h>

#ifdef CONFIG_RISCV_PMU

/*
 * The RISCV_MAX_COUNTERS parameter should be specified.
 */

#define RISCV_MAX_COUNTERS	64
#define RISCV_OP_UNSUPP		(-EOPNOTSUPP)
#define RISCV_PMU_PDEV_NAME	"riscv-pmu"
#define RISCV_PMU_LEGACY_PDEV_NAME	"riscv-pmu-legacy"

#define RISCV_PMU_STOP_FLAG_RESET 1

#define RISCV_PMU_CONFIG1_GUEST_EVENTS 0x1

#define MAX_BRANCH_RECORDS 256

struct branch_records {
	struct perf_branch_stack	branch_stack;
	struct perf_branch_entry	branch_entries[MAX_BRANCH_RECORDS];
};

struct cpu_hw_events {
	/* currently enabled events */
	int			n_events;
	/* Counter overflow interrupt */
	int		irq;
	/* currently enabled events */
	struct perf_event	*events[RISCV_MAX_COUNTERS];
	/* currently enabled hardware counters */
	DECLARE_BITMAP(used_hw_ctrs, RISCV_MAX_COUNTERS);
	/* currently enabled firmware counters */
	DECLARE_BITMAP(used_fw_ctrs, RISCV_MAX_COUNTERS);

    struct branch_records	*branches;
	
	/* Pointer to parent PMU structure. */
	struct riscv_pmu *pmu;
};

struct riscv_pmu {
	struct pmu	pmu;
	char		*name;

	irqreturn_t	(*handle_irq)(int irq_num, void *dev);

	unsigned long	cmask;
	u64		(*ctr_read)(struct perf_event *event);
	int		(*ctr_get_idx)(struct perf_event *event);
	int		(*ctr_get_width)(int idx);
	void		(*ctr_clear_idx)(struct perf_event *event);
	void		(*ctr_start)(struct perf_event *event, u64 init_val);
	void		(*ctr_stop)(struct perf_event *event, unsigned long flag);
	int		(*event_map)(struct perf_event *event, u64 *config);
    void    (*sched_task)(struct perf_event_pmu_context *pmu_ctx, bool sched_in);

	struct cpu_hw_events	__percpu *hw_events;
	struct hlist_node	node;
	struct notifier_block   riscv_pm_nb;

    bool has_ctr;
	
	/* Implementation specific attributes */
	void            *private;
};

#define to_riscv_pmu(p) (container_of(p, struct riscv_pmu, pmu))

void riscv_pmu_start(struct perf_event *event, int flags);
void riscv_pmu_stop(struct perf_event *event, int flags);
unsigned long riscv_pmu_ctr_read_csr(unsigned long csr);
int riscv_pmu_event_set_period(struct perf_event *event);
uint64_t riscv_pmu_ctr_get_width_mask(struct perf_event *event);
u64 riscv_pmu_event_update(struct perf_event *event);
#ifdef CONFIG_RISCV_PMU_LEGACY
void riscv_pmu_legacy_skip_init(void);
#else
static inline void riscv_pmu_legacy_skip_init(void) {};
#endif
struct riscv_pmu *riscv_pmu_alloc(void);
#ifdef CONFIG_RISCV_PMU_SBI
int riscv_pmu_get_hpm_info(u32 *hw_ctr_width, u32 *num_hw_ctr);
#endif

static inline bool riscv_pmu_ctr_supported(struct riscv_pmu *pmu)
{
	return pmu->has_ctr;
}

#endif /* CONFIG_RISCV_PMU */

#ifdef CONFIG_RISCV_CTR
void riscv_pmu_ctr_read(struct cpu_hw_events *cpuc, struct perf_event *event);
bool riscv_pmu_ctr_valid(struct perf_event *event);
void riscv_pmu_ctr_enable(struct perf_event *event);
void riscv_pmu_ctr_disable(struct perf_event *event);
void riscv_pmu_ctr_finish(struct riscv_pmu *riscv_pmu);
int riscv_pmu_ctr_init(struct riscv_pmu *riscv_pmu);
void riscv_pmu_ctr_reset(void);
void riscv_pmu_ctr_save(struct riscv_pmu *riscv_pmu, void *ctx);
void riscv_pmu_ctr_restore(void *ctx);
#else
static inline void riscv_pmu_ctr_read(struct cpu_hw_events *cpuc, struct perf_event *event)
{
       WARN_ON_ONCE(!has_branch_stack(event));
}

static inline bool riscv_pmu_ctr_valid(struct perf_event *event)
{
       WARN_ON_ONCE(!has_branch_stack(event));
       return false;
}

static inline void riscv_pmu_ctr_enable(struct perf_event *event)
{
       WARN_ON_ONCE(!has_branch_stack(event));
}

static inline void riscv_pmu_ctr_disable(struct perf_event *event)
{
       WARN_ON_ONCE(!has_branch_stack(event));
}

void riscv_pmu_ctr_finish(struct riscv_pmu *riscv_pmu) {return 0;}
int riscv_pmu_ctr_init(struct riscv_pmu *riscv_pmu) {}
static inline void riscv_pmu_ctr_reset(void) { }
static inline void riscv_pmu_ctr_save(struct riscv_pmu *riscv_pmu, void *ctx) { }
void riscv_pmu_ctr_restore(void *ctx) {}
#endif

#endif /* _ASM_RISCV_PERF_EVENT_H */
