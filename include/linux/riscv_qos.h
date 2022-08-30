// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2021 Arm Ltd.
// Copyright (C) 2022 Rivos Inc.
// RISC-V Sqos ISA extension support
// This file is based on arm_mpam.h

#ifndef __LINUX_RISCV_QOS_H
#define __LINUX_RISCV_QOS_H

#include <linux/resctrl_types.h>
#include <linux/iommu.h>
#include <linux/types.h>

#include <asm/qos.h>

/* Does the event count even when no context is allocated? */
static inline bool resctrl_arch_event_is_free_running(enum resctrl_event_id evt)
{

	return false;
}

static inline unsigned int resctrl_arch_round_mon_val(unsigned int val)
{
	/*
	 * This is only needed on Intel to implement Erratum SKX99/BDF102.
	 * No need to do anything here.
	 */
	return val;
}

bool resctrl_arch_alloc_capable(void);
bool resctrl_arch_mon_capable(void);
bool resctrl_arch_is_llc_occupancy_enabled(void);
bool resctrl_arch_is_mbm_local_enabled(void);
bool resctrl_arch_is_mbm_total_enabled(void);

/* reset cached configurations, then all devices */
void resctrl_arch_reset_resources(void);

bool resctrl_arch_get_cdp_enabled(enum resctrl_res_level ignored);
int resctrl_arch_set_cdp_enabled(enum resctrl_res_level ignored, bool enable);
bool resctrl_arch_match_closid(struct task_struct *tsk, u32 closid);
bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid);
void resctrl_arch_set_cpu_default_closid(int cpu, u32 closid);
void resctrl_arch_set_closid_rmid(struct task_struct *tsk, u32 closid, u32 rmid);
void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 pmg);
void resctrl_sched_in(void);
u32 resctrl_arch_rmid_idx_encode(u32 closid, u32 rmid);
void resctrl_arch_rmid_idx_decode(u32 idx, u32 *closid, u32 *rmid);
u32 resctrl_arch_system_num_rmid_idx(void);

/* TODO: Resources, describes what we support. */
struct rdt_resource;
int resctrl_arch_mon_ctx_alloc_no_wait(struct rdt_resource *r, int evtid);
void resctrl_arch_mon_ctx_free(struct rdt_resource *r, int evtid, int ctx);
struct rdt_resource *resctrl_arch_get_resource(enum resctrl_res_level l);

/* TODO: IOMMU support. */
static inline int resctrl_arch_set_iommu_closid_rmid(struct iommu_group *group, u32 closid, u32 rmid){ return 0; }
static inline bool resctrl_arch_match_iommu_closid(struct iommu_group *group, u32 closid) { return false; }
static inline bool resctrl_arch_match_iommu_closid_rmid(struct iommu_group *group, u32 closid, u32 rmid) { return false; }

/* TODO: Pseudo locking support. */
static inline int resctrl_arch_pseudo_lock_fn(void *_plr) { return 0; }
static inline int resctrl_arch_measure_l2_residency(void *_plr) { return 0; }
static inline int resctrl_arch_measure_l3_residency(void *_plr) { return 0; }
static inline int resctrl_arch_measure_cycles_lat_fn(void *_plr) { return 0; }
static inline u64 resctrl_arch_get_prefetch_disable_bits(void) { return 0; }

/* FIXME: Do we need to enable monitoring and resource control separately? */
static inline void resctrl_arch_enable_mon(void) { }
static inline void resctrl_arch_disable_mon(void) { }
static inline void resctrl_arch_enable_alloc(void) { }
static inline void resctrl_arch_disable_alloc(void) { }

#endif /* __LINUX_RISCV_QOS_H */
