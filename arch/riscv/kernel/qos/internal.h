// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2022 Rivos Inc.
#ifndef _ASM_RISCV_QOS_INTERNAL_H
#define _ASM_RISCV_QOS_INTERNAL_H

int qos_resctrl_setup(void);
void qos_resctrl_exit(void);
int qos_resctrl_online_cpu(unsigned int);
int qos_resctrl_offline_cpu(unsigned int);

#endif /* _ASM_RISCV_QOS_INTERNAL_H */
