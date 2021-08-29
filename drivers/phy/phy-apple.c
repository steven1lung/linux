// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/of.h>
#include <linux/irq.h>
#include <linux/platform_device.h>
#include <linux/usb/phy.h>

#define APPLE_PHY_USB2PHY_CONTROL 0x04
#define APPLE_PHY_USB2PHY_CONTROL_RESET BIT(0)
#define APPLE_PHY_USB2PHY_CONTROL_PORT_RESET BIT(1)

struct apple_phy {
	int irq;
	struct usb_phy phy;
	void __iomem *regs_phy;
	struct device *dev;
};

static irqreturn_t apple_phy_irq(int irq, void *cookie)
{
	//struct apple_phy *ap = cookie;
	//int i;

	// FIXME: this is wrong, will reset both ports
	return IRQ_WAKE_THREAD;
	;
#if 0
	// this is also wrong!
	u32 wtf = readl_relaxed(ap->regs_phy + 0x08);


	// FIXME: this is wrong
	if (wtf & BIT(20))
		return IRQ_WAKE_THREAD;
	else
		return IRQ_NONE;
#endif
}

static irqreturn_t apple_phy_irq_thread(int irq, void *cookie)
{
	struct apple_phy *ap = cookie;
	u32 control;

	control = readl_relaxed(ap->regs_phy + APPLE_PHY_USB2PHY_CONTROL);
	control |= APPLE_PHY_USB2PHY_CONTROL_PORT_RESET |
		   APPLE_PHY_USB2PHY_CONTROL_RESET;
	writel_relaxed(control, ap->regs_phy + APPLE_PHY_USB2PHY_CONTROL);

	udelay(30);
	control &= ~(APPLE_PHY_USB2PHY_CONTROL_PORT_RESET |
		     APPLE_PHY_USB2PHY_CONTROL_RESET);
	writel_relaxed(control, ap->regs_phy + APPLE_PHY_USB2PHY_CONTROL);

	return IRQ_HANDLED;
}

static int apple_phy_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct usb_phy *phy;
	struct apple_phy *ap;
	int ret;

	ap = devm_kzalloc(dev, sizeof(*ap), GFP_KERNEL);
	if (!ap)
		return -ENOMEM;

	ap->dev = dev;
	platform_set_drvdata(pdev, ap);

	ap->irq = platform_get_irq(pdev, 0);
	if (ap->irq < 0)
		return -EINVAL;

	ap->regs_phy = devm_platform_ioremap_resource_byname(pdev, "usb-phy");
	if (IS_ERR(ap->regs_phy))
		return PTR_ERR(ap->regs_phy);

	ret = devm_request_threaded_irq(&pdev->dev, ap->irq, apple_phy_irq,
					apple_phy_irq_thread, IRQF_SHARED,
					dev_name(dev), ap);
	if (ret)
		return ret;

	phy = &ap->phy;
	phy->dev = dev;
	phy->label = dev_name(dev);
	phy->type = USB_PHY_TYPE_USB2;

	return usb_add_phy_dev(phy);
}

static int apple_phy_remove(struct platform_device *pdev)
{
	struct apple_phy *ap = platform_get_drvdata(pdev);

	usb_remove_phy(&ap->phy);

	return 0;
}

static const struct of_device_id apple_phy_of_match[] = {
	{ .compatible = "apple,t8103-phy" },
	{}
};
MODULE_DEVICE_TABLE(of, apple_phy_of_match);

static struct platform_driver apple_phy_driver = {
	.driver = {
		.name = "apple-phy",
		.of_match_table = apple_phy_of_match,
	},
	.probe = apple_phy_probe,
	.remove = apple_phy_remove,
};

module_platform_driver(apple_phy_driver);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Sven Peter <sven@svenpeter.dev>");
MODULE_DESCRIPTION("Apple PHY driver");
