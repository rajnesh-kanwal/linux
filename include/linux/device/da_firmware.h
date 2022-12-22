/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Device authorization header file
 *
 * Copyright (C) 2023 Intel Corporation.
 */

#ifndef _DEVICE_DA_FIRMWARE_H_
#define _DEVICE_DA_FIRMWARE_H_

#include <linux/types.h>

#define NAME_LEN 64

/**
 * struct da_firmware_hdr - Common header for device authorization firmware.
 *
 * @major_ver: Major firmware version number.
 * @minor_ver:  Minor firmware version number.
 * @count: Total count of bus headers included in the firmware blob.
 * @type: Type of authorization list (ALLOW_LIST(0) or DENY_LIST(1)).
 */
struct da_firmware_hdr {
	__u32 major_ver, minor_ver;
	__u32 count;
	__u8 type;
	__u8 rsvd[7];
};

/**
 * struct da_bus_hdr - Bus header for device list.
 *
 * @bus: Name of the bus.
 * @count: Number of given bus device IDs included in the binary blob.
 */
struct da_bus_hdr {
	char bus[NAME_LEN];
	__u32 count;
};

#define PCI_ANY_ID (~0)

/**
 * struct da_pci_device_id - PCI Device ID structure.
 *
 * @vendor: Vendor PCI ID (or PCI_ANY_ID)
 * @device: Device PCI ID (or PCI_ANY_ID)
 * @subvendor: Subvendor PCI ID (or PCI_ANY_ID).
 * @subdevice: Subdevice PCI ID (or PCI_ANY_ID).
 * @class: Device class, subclass, and "interface" to match.
 * @class_mask: Limit which sub-fields of the class field are compared.
 */
struct da_pci_device_id {
	__u32 vendor, device;
	__u32 subvendor, subdevice;
	__u32 class, class_mask;
};

/**
 * struct da_bus_device_id - Common bus device ID structure (used
 *                           for bus's like ACPI, platform, etc).
 *
 * @name: Name of the device.
 */
struct da_bus_device_id {
	char name[NAME_LEN];
};

#endif
