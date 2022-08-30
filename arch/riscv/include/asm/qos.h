/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_QOS_H
#define _ASM_RISCV_QOS_H

#ifdef CONFIG_RISCV_CPU_QOSID

#include <linux/sched.h>
#include <linux/jump_label.h>

#include <asm/csr.h>
#include <asm/hwcap.h>

struct qos_cpu_state {
	u32 qoscfg;
	u32 def_qoscfg;
};

DECLARE_PER_CPU(struct qos_cpu_state, qos_cpu_state);

static void __qos_sched_in(struct task_struct *task)
{
	struct qos_cpu_state *state = this_cpu_ptr(&qos_cpu_state);
	u32 qoscfg;

	qoscfg = READ_ONCE(task->qoscfg);
	if (qoscfg == 0)
		qoscfg = READ_ONCE(state->def_qoscfg);

	BUG_ON((qoscfg & SQOSCFG_MASK) != qoscfg);

	if (qoscfg != state->qoscfg) {
		state->qoscfg = qoscfg;
		csr_write(CSR_SQOSCFG, qoscfg);
	}
}

static inline void qos_sched_in(struct task_struct *task)
{

	if (static_branch_likely(&riscv_isa_ext_keys[RISCV_ISA_EXT_KEY_SSQOSID])) {
		__qos_sched_in(task);
	}
}
#else

static inline void qos_sched_in(struct task_struct *task){}

#endif /* CONFIG_RISCV_CPU_QOS */
#endif	/* _ASM_X86_QOS_H */

