// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Rivos Inc.
 *
 * Authors:
 *     Rajnesh Kanwal <rkanwal@rivosinc.com>
 */

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <asm/teeg_sbi.h>
#include <asm-generic/io.h>

/**
 * ioremap_driver_hardened - map memory into CPU space and register
 * with host for emulation.
 *
 * @phys_addr:	bus address of the memory
 * @size:	size of the resource to map
 *
 * This version of ioremap ensures that the memory is registered
 * with the host when it used by a hardened driver.
 * This is useful for confidential guests.
 *
 * Note that drivers should not use this function directly, but use
 * pci_iomap_range() or devm_ioremap().
 *
 * Must be freed with iounmap_driver_hardened.
 */
void __iomem *ioremap_driver_hardened(phys_addr_t addr, size_t size)
{
	unsigned long offset;

	void __iomem *p = ioremap(addr, size);
	if (!p)
		return NULL;

	/* Page-align address and size. */
	offset = addr & (~PAGE_MASK);
	addr -= offset;
	size = PAGE_ALIGN(size + offset);

	sbi_teeg_add_mmio_region(addr, size);
	return p;
}
EXPORT_SYMBOL(ioremap_driver_hardened);

void iounmap_driver_hardened(void __iomem *addr)
{
	void *vaddr = (void *)((unsigned long)addr & PAGE_MASK);
	struct vm_struct *area;

	area = find_vm_area(vaddr);
	if (unlikely(!area)) {
		WARN(1, KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n",
		     addr);
		return;
	}

	sbi_teeg_remove_mmio_region((uintptr_t)area->addr,
				    get_vm_area_size(area));

	iounmap(addr);
}
EXPORT_SYMBOL(iounmap_driver_hardened);
