// SPDX-License-Identifier: GPL-2.0

#include <linux/bitops.h>
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mailbox_controller.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/spinlock.h>
#include <linux/pm_runtime.h>
#include "../mailbox.h"
#include "k1x_mailbox.h"

#define mbox_dbg(mbox, ...)	dev_dbg((mbox)->controller.dev, __VA_ARGS__)

static irqreturn_t spacemit_mbox_irq(int irq, void *dev_id)
{
	struct spacemit_mailbox *mbox = dev_id;
	struct mbox_chan *chan;
	unsigned int status, msg = 0;
	int i;

	writel(0, (void __iomem *)&mbox->regs->ipc_iir);

	status = readl((void __iomem *)&mbox->regs->ipc_iir);

	if (!(status & 0xff))
		return IRQ_NONE;

	for (i = SPACEMIT_TX_ACK_OFFSET; i < SPACEMIT_NUM_CHANNELS + SPACEMIT_TX_ACK_OFFSET; ++i) {
		chan = &mbox->controller.chans[i - SPACEMIT_TX_ACK_OFFSET];
		/* new msg irq */
		if (!(status & (1 << i)))
			continue;

		/* clear the irq pending */
		writel(1 << i, (void __iomem *)&mbox->regs->ipc_icr);

		if (chan->txdone_method & TXDONE_BY_IRQ)
			mbox_chan_txdone(chan, 0);
	}

	for (i = 0; i < SPACEMIT_NUM_CHANNELS; ++i) {
		chan = &mbox->controller.chans[i];

		/* new msg irq */
		if (!(status & (1 << i)))
			continue;

		mbox_chan_received_data(chan, &msg);

		/* clear the irq pending */
		writel(1 << i, (void __iomem *)&mbox->regs->ipc_icr);
	}

	return IRQ_HANDLED;
}

static int spacemit_chan_send_data(struct mbox_chan *chan, void *data)
{
	unsigned long flag;
	struct spacemit_mailbox *mbox = ((struct spacemit_mb_con_priv *)chan->con_priv)->smb;
	unsigned int chan_num = chan - mbox->controller.chans;

	spin_lock_irqsave(&mbox->lock, flag);

	writel(1 << chan_num, (void __iomem *)&mbox->regs->ipc_isrw);

	spin_unlock_irqrestore(&mbox->lock, flag);

	mbox_dbg(mbox, "Channel %d sent 0x%08x\n", chan_num, *((unsigned int *)data));

	return 0;
}

static int spacemit_chan_startup(struct mbox_chan *chan)
{
	return 0;
}

static void spacemit_chan_shutdown(struct mbox_chan *chan)
{
	unsigned int j;
	unsigned long flag;
	struct spacemit_mailbox *mbox = ((struct spacemit_mb_con_priv *)chan->con_priv)->smb;
	unsigned int chan_num = chan - mbox->controller.chans;

	spin_lock_irqsave(&mbox->lock, flag);

	/* clear pending */
	j = 0;
	j |= (1 << chan_num);
	writel(j, (void __iomem *)&mbox->regs->ipc_icr);

	spin_unlock_irqrestore(&mbox->lock, flag);
}

static bool spacemit_chan_last_tx_done(struct mbox_chan *chan)
{
	return 0;
}

static bool spacemit_chan_peek_data(struct mbox_chan *chan)
{
	struct spacemit_mailbox *mbox = ((struct spacemit_mb_con_priv *)chan->con_priv)->smb;
	unsigned int chan_num = chan - mbox->controller.chans;

	return readl((void __iomem *)&mbox->regs->ipc_rdr) & (1 << chan_num);
}

static const struct mbox_chan_ops spacemit_chan_ops = {
	.send_data    = spacemit_chan_send_data,
	.startup      = spacemit_chan_startup,
	.shutdown     = spacemit_chan_shutdown,
	.last_tx_done = spacemit_chan_last_tx_done,
	.peek_data    = spacemit_chan_peek_data,
};

static int spacemit_mailbox_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mbox_chan *chans;
	struct spacemit_mailbox *mbox;
	struct spacemit_mb_con_priv *con_priv;
	int i, ret;

	mbox = devm_kzalloc(dev, sizeof(*mbox), GFP_KERNEL);
	if (!mbox)
		return -ENOMEM;

	con_priv = devm_kzalloc(dev, sizeof(*con_priv) * SPACEMIT_NUM_CHANNELS, GFP_KERNEL);
	if (!con_priv)
		return -ENOMEM;

	chans = devm_kcalloc(dev, SPACEMIT_NUM_CHANNELS, sizeof(*chans), GFP_KERNEL);
	if (!chans)
		return -ENOMEM;

	for (i = 0; i < SPACEMIT_NUM_CHANNELS; ++i) {
		con_priv[i].smb = mbox;
		chans[i].con_priv = con_priv + i;
	}

	mbox->dev = dev;

	mbox->regs = (mbox_reg_desc_t *)devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(mbox->regs)) {
		ret = PTR_ERR(mbox->regs);
		dev_err(dev, "Failed to map MMIO resource: %d\n", ret);
		return -EINVAL;
	}

	mbox->reset = devm_reset_control_get_exclusive(dev, "core_reset");
	if (IS_ERR(mbox->reset)) {
		ret = PTR_ERR(mbox->reset);
		dev_err(dev, "Failed to get reset: %d\n", ret);
		return -EINVAL;
	}

	/* deasser clk  */
	ret = reset_control_deassert(mbox->reset);
	if (ret) {
		dev_err(dev, "Failed to deassert reset: %d\n", ret);
		return -EINVAL;
	}

	pm_runtime_enable(dev);
	pm_runtime_get_sync(dev);
	pm_runtime_get_noresume(dev);

	/* request irq */
	ret = devm_request_irq(dev, platform_get_irq(pdev, 0),
			       spacemit_mbox_irq, 0, dev_name(dev), mbox);
	if (ret) {
		dev_err(dev, "Failed to register IRQ handler: %d\n", ret);
		return -EINVAL;
	}

	/* register the mailbox controller */
	mbox->controller.dev           = dev;
	mbox->controller.ops           = &spacemit_chan_ops;
	mbox->controller.chans         = chans;
	mbox->controller.num_chans     = SPACEMIT_NUM_CHANNELS;
	mbox->controller.txdone_irq    = true;
	mbox->controller.txdone_poll   = false;
	mbox->controller.txpoll_period = 5;

	spin_lock_init(&mbox->lock);
	platform_set_drvdata(pdev, mbox);

	ret = mbox_controller_register(&mbox->controller);
	if (ret) {
		dev_err(dev, "Failed to register controller: %d\n", ret);
		return -EINVAL;
	}

	return 0;
}

static int spacemit_mailbox_remove(struct platform_device *pdev)
{
	struct spacemit_mailbox *mbox = platform_get_drvdata(pdev);

	mbox_controller_unregister(&mbox->controller);

	pm_runtime_put_noidle(&pdev->dev);
	pm_runtime_put_sync(&pdev->dev);

	return 0;
}

static const struct of_device_id spacemit_mailbox_of_match[] = {
	{ .compatible = "spacemit,k1-x-mailbox", },
	{},
};
MODULE_DEVICE_TABLE(of, spacemit_mailbox_of_match);

static struct platform_driver spacemit_mailbox_driver = {
	.driver = {
		.name = "spacemit-mailbox",
		.of_match_table = spacemit_mailbox_of_match,
	},
	.probe  = spacemit_mailbox_probe,
	.remove = spacemit_mailbox_remove,
};
module_platform_driver(spacemit_mailbox_driver);

MODULE_DESCRIPTION("spacemit Message Box driver");
MODULE_LICENSE("GPL v2");
