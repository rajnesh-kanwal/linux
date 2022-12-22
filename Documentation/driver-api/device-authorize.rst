.. SPDX-License-Identifier: GPL-2.0

Introduction:
=============

Device authorize (DA) support adds support to selectively authorize the
enumeration of the devices. Currently the default device authorization status
of all devices is controlled via "device.authorize.all" kernel command line
option. But this level of control is insufficient for confidential computing
use cases (like TDX), where the host is an untrusted entity and the guest would
want to allow only a specific list of devices. To handle such cases, device
core "authorized" support is extended to allow the user to provide the platform
specific allow/deny list as a firmware blob. The following section explains the
details and format of the firmware blob.

1. Firmware Structure Layout
=============================

The user can provide the platform specific device authorization allow/deny list
as a binary blob. The firmware can be added to the initrd (in /lib/firmware),
and its name is passed to kernel via the "device.authorize.firmware" kernel
command line option.

The firmware binary should start with da_firmware_hdr which includes details
about the firmware like, version, total bus count, etc. And each bus section
should start with bus specific da_bus_hdr followed by bus specific device ids.

Following is the sample structure of the firmware blob.

----------------------------------------------------
|             struct da_firmware_hdr               |
|                (type=0, count=2)                 |
----------------------------------------------------
|             struct da_bus_hdr                    |
|              (bus="pci", count=2)                |
----------------------------------------------------
|             struct da_pci_devce_id               |
|                                                  |
----------------------------------------------------
|             struct da_pci_device_id              |
|                                                  |
----------------------------------------------------
|             struct da_bus_hdr                    |
|              (bus="platform", count=2)           |
----------------------------------------------------
|             struct da_bus_device_id              |
|                                                  |
----------------------------------------------------
|             struct da_bus_device_id              |
|                                                  |
----------------------------------------------------

Following are the details of structs involved in the binary blob.

/**
 * struct da_firmware_hdr - Common header of device authorize firmware.
 *
 * @major_ver: Major firmware version number.
 * @minor_ver:  Minor firmware version number.
 * @count: Count of bus headers included in the firmware blob.
 */
struct da_firmware_hdr {
        __u32 major_ver, minor_ver;
        __u32 count;
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
