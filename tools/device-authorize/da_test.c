// SPDX-License-Identifier: GPL-2.0
/*
 * Device authorize test module
 *
 * Copyright (C) 2023 Intel Corporation
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/platform_device.h>

#define DRIVER_NAME "da_test"

static struct platform_device *pdev;

static int da_test_probe(struct platform_device *pdev)
{
	dev_info(&pdev->dev, "%s:%d\n", __func__, __LINE__);
	return 0;
}

static int da_test_remove(struct platform_device *pdev)
{
	dev_info(&pdev->dev, "%s:%d\n", __func__, __LINE__);
	return 0;
}


static struct platform_driver da_test_driver = {
	.probe = da_test_probe,
	.remove = da_test_remove,
	.driver.name = DRIVER_NAME,
};

static int __init da_test_init(void)
{
	int ret;

	ret = platform_driver_register(&da_test_driver);
	if (ret) {
		pr_err("%s driver register failed\n", DRIVER_NAME);
		return ret;
	}

	pdev = platform_device_alloc(DRIVER_NAME, -1);
	if (!pdev) {
		pr_err("%s device alloc failed\n", DRIVER_NAME);
		ret = -ENODEV;
		goto fail_register;
	}

	pdev->dev.authorized = 0;

	ret = platform_device_add(pdev);
	if (ret) {
		platform_device_put(pdev);
		goto fail_register;
	}

	return 0;

fail_register:
	platform_driver_unregister(&da_test_driver);
	return ret;
}

static void __exit da_test_exit(void)
{
	platform_driver_unregister(&da_test_driver);
	platform_device_unregister(pdev);
}
module_init(da_test_init);
module_exit(da_test_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("Device authorize test module");
MODULE_LICENSE("GPL");
