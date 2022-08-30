// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2022 Rivos Inc.

#define pr_fmt(fmt) "qos: resctrl: " fmt

#include <linux/slab.h>
#include <linux/err.h>
#include <linux/riscv_qos.h>
#include <linux/resctrl.h>

#include <asm/csr.h>
#include <asm/qos.h>

#include "internal.h"

static struct rdt_resource qos_resctrl_exports[RDT_NUM_RESOURCES];

/*
 * XXX: We need to fake that at least one of the features
 * (monitoring/resource control) is available.
 * Otherwise the resctrl FS won't be usable.
 * This should be discovered from DT/ACPI, based on device capabilities.
 */
bool resctrl_arch_alloc_capable()
{
	return true;
}

bool resctrl_arch_mon_capable()
{
	return true;
}

bool resctrl_arch_is_mbm_local_enabled()
{
	return false;
}

bool resctrl_arch_is_mbm_total_enabled()
{
	return false;
}

bool resctrl_arch_get_cdp_enabled(enum resctrl_res_level rid)
{
	return false;
}

int resctrl_arch_set_cdp_enabled(enum resctrl_res_level ignored, bool enable)
{
	return -ENODEV;
}

bool resctrl_arch_is_llc_occupancy_enabled()
{
	return false;
}

u32 resctrl_arch_get_num_closid(struct rdt_resource *res)
{
	/* FIXME: Read the number of available IDs from ACPI/DT. */
	return 16;
}

u32 resctrl_arch_system_num_rmid_idx()
{
	/* FIXME: Read the number of available IDs from ACPI/DT. */
	return 16;
}

u32 resctrl_arch_rmid_idx_encode(u32 closid, u32 rmid)
{
	/*
	 * In ARM MPAM rmid is kind of tied to closid.
	 * Since those two IDs are orthogonal on RISC-V there is
	 * no need to apply any translation here.
	 */
	BUG_ON((rmid & SQOSCFG_MCID_MASK) != rmid);

	return rmid;
}

void resctrl_arch_rmid_idx_decode(u32 idx, u32 *closid, u32 *rmid)
{

	BUG_ON((idx & SQOSCFG_MCID_MASK) != idx);

	*closid = 0;
	*rmid = idx;
}

void resctrl_sched_in()
{

	lockdep_assert_preemption_disabled();
	qos_sched_in(current);
}

void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 rmid)
{

	/* XXX: This is redundant with resctrl_arch_sync_cpu_defaults. */
}

void resctrl_arch_sync_cpu_defaults(void *info)
{
	struct qos_cpu_state *state = this_cpu_ptr(&qos_cpu_state);
	struct resctrl_cpu_sync *r = info;
	u32 qoscfg;

	if (r == NULL)
		return;

	BUG_ON((r->closid & SQOSCFG_RCID_MASK) != r->closid);
	BUG_ON((r->rmid & SQOSCFG_MCID_MASK) != r->rmid);

	qoscfg = r->rmid << SQOSCFG_MCID_SHIFT;
	qoscfg |= r->closid;
	WRITE_ONCE(state->def_qoscfg, qoscfg);
	resctrl_sched_in();
}

void resctrl_arch_set_closid_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	u32 qoscfg;

	BUG_ON((closid & SQOSCFG_RCID_MASK) != closid);
	BUG_ON((rmid & SQOSCFG_MCID_MASK) != rmid);

	qoscfg = rmid << SQOSCFG_MCID_SHIFT;
	qoscfg |= closid;
	WRITE_ONCE(tsk->qoscfg, qoscfg);
}

bool resctrl_arch_match_closid(struct task_struct *tsk, u32 closid)
{
	u32 qoscfg;

	qoscfg = READ_ONCE(tsk->qoscfg);

	return (qoscfg & SQOSCFG_RCID_MASK) == closid;
}

bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	u32 tsk_rmid;

	tsk_rmid = READ_ONCE(tsk->qoscfg);
	tsk_rmid >>= SQOSCFG_MCID_SHIFT;
	tsk_rmid &= SQOSCFG_MCID_MASK;

	return tsk_rmid == rmid;
}

struct rdt_resource *resctrl_arch_get_resource(enum resctrl_res_level l)
{
	if (l >= RDT_NUM_RESOURCES)
		return NULL;

	return &qos_resctrl_exports[l];
}

int resctrl_arch_mon_ctx_alloc_no_wait(struct rdt_resource *r, int evtid)
{
	return -EOPNOTSUPP;
}

void resctrl_arch_mon_ctx_free(struct rdt_resource *r, int evtid, int ctx)
{
	return;
}

int resctrl_arch_rmid_read(struct rdt_resource  *r, struct rdt_domain *d,
			   u32 closid, u32 rmid, enum resctrl_event_id eventid,
			   u64 *val, int arch_mon_ctx)
{
	return -EOPNOTSUPP;
}

void resctrl_arch_reset_rmid(struct rdt_resource *r, struct rdt_domain *d,
			     u32 closid, u32 rmid, enum resctrl_event_id eventid)
{
	return;
}

u32 resctrl_arch_get_config(struct rdt_resource *r, struct rdt_domain *d,
			    u32 closid, enum resctrl_conf_type type)
{
	return -EINVAL;
}

int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_domain *d,
			    u32 closid, enum resctrl_conf_type t, u32 cfg_val)
{
	return -EINVAL;
}

int resctrl_arch_update_domains(struct rdt_resource *r, u32 closid)
{
	return -EINVAL;
}

void resctrl_arch_reset_resources(void)
{
	return;
}

struct rdt_domain *resctrl_arch_find_domain(struct rdt_resource *r, int id)
{
	return NULL;
}

static void qos_resctrl_setup_resources(void)
{
	struct rdt_resource *res;

	res = &qos_resctrl_exports[RDT_RESOURCE_L2];
	res->rid = RDT_RESOURCE_L2;
	res->fflags = RFTYPE_RES_CACHE;
	INIT_LIST_HEAD(&res->domains);
	INIT_LIST_HEAD(&res->evt_list);
	res->name = "L2";

	res = &qos_resctrl_exports[RDT_RESOURCE_L3];
	res->rid = RDT_RESOURCE_L3;
	res->fflags = RFTYPE_RES_CACHE;
	INIT_LIST_HEAD(&res->domains);
	INIT_LIST_HEAD(&res->evt_list);
	res->name = "L3";

	res = &qos_resctrl_exports[RDT_RESOURCE_MBA];
	res->rid = RDT_RESOURCE_MBA;
	INIT_LIST_HEAD(&res->domains);
	INIT_LIST_HEAD(&res->evt_list);
	res->name = "MB";
}

int qos_resctrl_setup()
{
	u32 err;

	qos_resctrl_setup_resources();
	err = resctrl_init();

	return err;
}

void qos_resctrl_exit()
{
	resctrl_exit();
}

int qos_resctrl_online_cpu(unsigned int cpu)
{

	return resctrl_online_cpu(cpu);

}
int qos_resctrl_offline_cpu(unsigned int cpu)
{

	resctrl_offline_cpu(cpu);
	return 0;
}
