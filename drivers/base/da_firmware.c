// SPDX-License-Identifier: GPL-2.0
/*
 * Device authorization firmware support
 *
 * Copyright (C) 2022 Intel Corporation
 */

#define pr_fmt(fmt) "da-firmware: " fmt

#include <linux/earlycpio.h>
#include <linux/fs.h>
#include <linux/initrd.h>
#include <linux/firmware.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/mod_devicetable.h>
#include <linux/device/da_firmware.h>

/**
 * struct da_bus_node - DA firmware bus node struct.
 *
 * @name: Name of the bus.
 * @count: Number of the devices.
 * @dev_ids: Array of device ids.
 * @parse_devices: Handler to parse BUS specific devices in DA firmware.
 *                 Return 0 on failure or size of data parsed on success.
 * @match_device: Handle to find the given device in dev_ids list.
 *                return True if the device is found in dev_ids list.
 * @print_info: Print device info of all devices in dev_ids list.
 */
struct da_bus_node {
	char name[NAME_LEN];
	u32 count;
	void *dev_ids;
	struct list_head list;
	size_t (*parse_devices)(struct da_bus_node *node, void *entry);
	bool (*match_device)(struct da_bus_node *node, struct device *dev);
	void (*print_info)(struct da_bus_node *node);

};

/* List of parsed DA bus nodes */
static LIST_HEAD(platform_da_list);

/* Flag to track initialization status of DA firmware parser */
static bool init_done;

/* Type of the DA list 0 for allow list or 1 for deny list */
static u8 da_list_type;

static char *firmware_name = "NA";

/* Command line parser for DA firmware name */
static int __init da_firmware_cmdline_setup(char *str)
{
	firmware_name = str;
	return 1;
}
__setup("device.authorize.firmware=", da_firmware_cmdline_setup);

static size_t pci_parse_devices(struct da_bus_node *node, void *data)
{
	struct da_pci_device_id *da_id = data;
	struct pci_device_id *ids;
	unsigned int i;

	ids = kmalloc_array(node->count, sizeof(*ids), GFP_KERNEL | __GFP_ZERO);
	if (!ids)
		return 0;

	for (i = 0; i < node->count; i++)
		memcpy(&ids[i], &da_id[i], sizeof(*da_id));

	node->dev_ids = ids;

	return sizeof(*da_id) * node->count;
}

static bool pci_match_device(struct da_bus_node *node, struct device *dev)
{
	const struct pci_device_id *ids = node->dev_ids;

	if (pci_match_id(ids, to_pci_dev(dev)))
		return true;

	return false;
}

static void pci_print_info(struct da_bus_node *node)
{
	struct pci_device_id *ids =  node->dev_ids;
	int i;

	pr_debug("List of PCI bus devices\n");

	for (i = 0; i < node->count; i++)
		pr_debug("PCI device %x:%x %x:%x\n", ids[i].vendor,
			 ids[i].device, ids[i].subvendor, ids[i].subdevice);
}

static bool bus_match_device(struct da_bus_node *node, struct device *dev)
{
	struct da_bus_device_id *ids = node->dev_ids;
	int i;

	for (i = 0; i < node->count; i++)
		if (!strncmp(ids[i].name, dev_name(dev), strlen(ids[i].name)))
			return true;

	return false;
}

static size_t bus_parse_devices(struct da_bus_node *node, void *data)
{
	struct da_bus_device_id *ids;

	ids = kmalloc_array(node->count, sizeof(*ids), GFP_KERNEL);
	if (!ids)
		return 0;

	memcpy(ids, data, sizeof(*ids) * node->count);

	node->dev_ids = ids;

	return sizeof(*ids) * node->count;
}

static void bus_print_info(struct da_bus_node *node)
{
	struct da_bus_device_id *ids =  node->dev_ids;
	int i;

	pr_debug("List of %s bus devices\n", node->name);

	for (i = 0; i < node->count; i++)
		pr_debug("%s device %s\n", node->name, ids[i].name);
}

/* Allocate DA firmware bus node and initialize it based on struct da_bus_hdr */
static struct da_bus_node *alloc_bus_node(struct da_bus_hdr *hdr)
{
	struct da_bus_node *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;

	strncpy(node->name, hdr->bus, NAME_LEN);
	node->count = hdr->count;

	if (!strncmp(hdr->bus, "pci", 3)) {
		node->parse_devices = pci_parse_devices;
		node->match_device = pci_match_device;
		node->print_info = pci_print_info;
	} else {
		node->parse_devices = bus_parse_devices;
		node->match_device = bus_match_device;
		node->print_info = bus_print_info;
	}

	list_add_tail(&node->list, &platform_da_list);

	return node;
}

static void free_platform_da_list(void)
{
	struct da_bus_node *node, *tmp_node;

	list_for_each_entry_safe(node, tmp_node, &platform_da_list, list) {
		kfree(node->dev_ids);
		list_del(&node->list);
		kfree(node);
	}
}

static void print_platform_da_list(void)
{
	struct da_bus_node *node;

	list_for_each_entry(node, &platform_da_list, list)
		node->print_info(node);
}

/**
 * platform_dev_authorized() - Check whether the device is in platform
 *                             specific DA firmware allow or deny list.
 * @dev: Struct device of the device to be checked.
 *
 * This helper can be used by bus drivers before device_add() or
 * device_register() to lookup the device platform specific initialization
 * status of the given device.
 *
 * Return true if the device is authorized to enumerate, false if the device is
 * unauthorized or dev->authorized for all other cases.
 */
bool platform_dev_authorized(struct device *dev)
{
	const char *bus = dev_bus_name(dev);
	struct da_bus_node *node;
	bool status = false;

	/* If not initialized or invalid params, return default value */
	if (!init_done || !dev->bus || !strlen(bus))
		return dev->authorized;

	list_for_each_entry(node, &platform_da_list, list) {
		if (!strncmp(bus, node->name, strlen(node->name))) {
			/*
			 * If no device entries exist for the given bus,
			 * allow all in that bus.
			 */
			if (node->count)
				status = node->match_device(node, dev);
			else
				status = true;
			if (status)
				break;
		}
	}

	dev_dbg(dev, "Platform authorized status: %d\n", status);

	/* If the list type is deny list, inverse the result */
	return !da_list_type ? status : !status;
}
EXPORT_SYMBOL_GPL(platform_dev_authorized);

static int __init parse_firmware_data(struct cpio_data *cpio)
{
	struct da_firmware_hdr *fhdr = cpio->data;
	void *cur = cpio->data, *end;
	struct da_bus_node *bnode;
	struct da_bus_hdr *bhdr;
	size_t size;

	pr_debug("firmware version: %d.%d type: %d count: %d\n",
		 fhdr->major_ver, fhdr->minor_ver, fhdr->type, fhdr->count);

	da_list_type = fhdr->type;

	cur = cur + sizeof(*fhdr);
	end = cur + cpio->size - sizeof(struct da_bus_hdr);

	while (cur <= end) {
		bhdr = (struct da_bus_hdr *)cur;
		bnode = alloc_bus_node(bhdr);
		pr_debug("parsing %s node count:%d\n", bnode->name, bnode->count);
		cur =  cur + sizeof(*bhdr);
		if (!bnode)
			goto out;
		size = bnode->parse_devices(bnode, cur);
		cur = cur + size;
	}

	return 0;

out:
	free_platform_da_list();
	return -EINVAL;
}

static bool __init da_get_firmware(struct cpio_data *blob, const char *name)
{
	const char *search_path[] = {
		"lib/firmware/%s",
		"usr/lib/firmware/%s",
		"opt/intel/%s"
	};
	struct firmware fw;
	char path[64];
	long offset;
	size_t size;
	void *data;
	int i;

	if (firmware_request_builtin(&fw, name)) {
		blob->size = fw.size;
		blob->data = (void *)fw.data;
		return true;
	}

	if (!IS_ENABLED(CONFIG_BLK_DEV_INITRD) || !initrd_start)
		return false;

	for (i = 0; i < ARRAY_SIZE(search_path); i++) {
		offset = 0;
		data = (void *)initrd_start;
		size = initrd_end - initrd_start;
		snprintf(path, sizeof(path), search_path[i], name);
		while (size > 0) {
			*blob = find_cpio_data(path, data, size, &offset);

			/* find the filename, the returned blob name is empty */
			if (blob->data && blob->name[0] == '\0')
				return true;

			if (!blob->data)
				break;

			/* match the item with the same path prefix, skip it*/
			data += offset;
			size -= offset;
		}
	}

	return false;
}

static int __init da_firmware_init(void)
{
	struct cpio_data da_firmware_cpio;

	pr_info("Using firmware name %s", firmware_name);

	if (!da_get_firmware(&da_firmware_cpio, firmware_name)) {
		pr_err("Cannot load firmware\n");
		return -EIO;
	}

	if (parse_firmware_data(&da_firmware_cpio)) {
		pr_err("Parsing %s firmware failed\n", firmware_name);
		return -EIO;
	}

	init_done = true;

	print_platform_da_list();

	return 0;
}
arch_initcall(da_firmware_init);
