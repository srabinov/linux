
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/swap.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/oom.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/types.h>
#include <linux/cdev.h>

#define TEST_PCI_DEBG

#if defined (TEST_PCI_DEBG)
	#define test_pci_debug(format, ...) pr_err("## %s (%.3d) : " format, __func__, __LINE__, ## __VA_ARGS__ )
#else
	#define test_pci_debug(format, ...)
#endif

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_TEST_PCI, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

/* use for ioctl */
typedef struct test_ioctl_data {
} test_ioctl_data;

#define TEST_PCI_MAGIC 123 // 8bit
#define VIRTTESTPCI_IOCTL_DEV_PING _IOR(TEST_PCI_MAGIC, 0, test_ioctl_data)

enum virttrstpci_op {
	/* driver -> dev */

	/* test the driver - hw communication */
	VIRTTESTPCI_OP_DEV_PING = 0,
};

enum virttrstpci_complete_status {
	VIRTTESTPCI_OP_STAT_SUCCESS = 0,
	VIRTTESTPCI_OP_STAT_ERR,
};

struct virttrstpci_sg {
	__be64	addr;
	__be64	len;
};

/* commands/events excahanged between the guest driver and the emulated hw */

struct virttrstpci_cmd {
	/* seq number of this command (can be matched with ack cmd_seq) */
	__be64	seq; 
	/* op of this command (select the below struct from union) */
	__be16 	op;
	u16	pad1;
	u32	pad2; 
	union {
		struct {
			__be64	pad3;
		} foo;
	} cmd;
};

/*
 * each command has matching completion event so the event
 * seq equal the command seq and can tell the command and
 * event index in the ring.
 */
struct virttrstpci_event {
	__be64  seq;
	__be16  op;
	__be16	status;
	u32	pad1;
	union {
		struct {
			__be64	pad2;
		} foo;
	} event;
};

#define VIRTTESTPCI_RING_SIZE	(64)

/* test_pci device context attached to the virtio device */
struct virttestpci_ctx {
	struct virtio_device	*vdev;
	struct virtqueue	*vq_cmd; 
	struct virtqueue	*vq_event; 
	wait_queue_head_t	 cmd_acked;
	wait_queue_head_t	 event_acked;
	struct cdev		*cdev;	
	u64			 ring_seq;
	u16			 ring_head; /* 0 <= ring_head <= VIRTTESTPCI_RING_SIZE-1*/
	u16 			 ring_tail; /* 0 <= ring_tail <= VIRTTESTPCI_RING_SIZE-1*/
	struct virttrstpci_cmd	 cmd_ring[VIRTTESTPCI_RING_SIZE];
	struct virttrstpci_event event_ring[VIRTTESTPCI_RING_SIZE];
	atomic_t		 stop; /* stop command and events waiters */
	struct completion	 cmp_cmd;
};

static inline u16 ring_inc(u16 index)
{
	return (++index % VIRTTESTPCI_RING_SIZE);
}

static inline u16 ring_dec(u16 index)
{
	return (((index + VIRTTESTPCI_RING_SIZE) - 1) %
                VIRTTESTPCI_RING_SIZE);
}

static inline bool ring_full(u16 ring_head, u16 ring_tail)
{
	return ((++ring_head % VIRTTESTPCI_RING_SIZE) == ring_tail); 
}

/* TODO: we only support 1 device context (hw) */
static struct virttestpci_ctx *dev_ctx; 

static DEFINE_MUTEX(virttestpci_vq_lock);

static int virttestpci_wait_for_cmd_ack(struct virttestpci_ctx *ctx)
{
	struct virttrstpci_cmd *cmd;
	int len;
	int ret;

	test_pci_debug("wait...\n");

	/* wait for hw to read the command */
	ret = wait_event_interruptible(ctx->cmd_acked,
		virtqueue_get_buf(ctx->vq_cmd,
		&len) || atomic_read(&ctx->stop));

	if (ret) {
		test_pci_debug("cmd ack interrupted!\n");
		return -EINTR;
	}

	/* len is only valid for hw->driver (event) path */

	cmd = &ctx->cmd_ring[ctx->ring_head];
	test_pci_debug("cmd ack! seq %llu\n", be64_to_cpu(cmd->seq));
	return 0;
}

static int virttestpci_wait_for_event_ack(struct virttestpci_ctx *ctx)
{
	struct virttrstpci_event *event;
	int len;
	int ret;

	/* wait for hw to write the event */
	for (;;) {
		test_pci_debug("wait...\n");

		ret = wait_event_interruptible(ctx->event_acked,
			virtqueue_get_buf(ctx->vq_event,
			&len) || atomic_read(&ctx->stop));
		
		if (ret) {
			test_pci_debug("event ack interrupted!\n");
			return -EINTR;
		}
		
		if (len != sizeof(struct virttrstpci_event)) {
			test_pci_debug("inv len (sporious INT?): len %u expext %lu\n",
				len, sizeof(struct virttrstpci_event));
			continue;
		}

		/* we are done! */
		break;
	}

	event = &ctx->event_ring[ctx->ring_head];
	test_pci_debug("event ack! seq %llu\n", be64_to_cpu(event->seq));
	return 0;
}

static int virttestpci_wait_for_cmd_complete(struct virttestpci_ctx *ctx)
{
	int ret;

	test_pci_debug("enter\n");

	if ((ret = virttestpci_wait_for_cmd_ack(ctx)))
		goto error;

	if ((ret = virttestpci_wait_for_event_ack(ctx)))
		goto error;

	ctx->ring_tail = ring_inc(ctx->ring_tail);

error:
	return ret;
}

/**
 * virttestpci_post_cmd - this function check if the command ring has
 *  room for new cmmand, if yes - inc the ring head, push the command 
 *  to the ring, post the matching event from the event ring and wait
 *  for the hw to write the completion event 
 * @ctx - virtio device conext
 * @cmd	- command that we wish to send via the device command ring
 * @event - the event returned by the hw for this comamnd
 */
static int virttestpci_post_cmd(struct virttestpci_ctx *ctx,
				struct virttrstpci_cmd *cmd,
				struct virttrstpci_event *event)
{
	struct virttrstpci_cmd 		*ring_cmd;
	struct virttrstpci_event	*ring_event;
	struct scatterlist		cmd_sg, event_sg;
	int				ret = 0;

	mutex_lock(&virttestpci_vq_lock);

	if (atomic_read(&ctx->stop)) {
		test_pci_debug("ctx is stopped!\n");
		ret = -EINVAL;
		goto error;
	}

	if (ring_full(ctx->ring_head, ctx->ring_tail)) {
		test_pci_debug("ring full! abort!\n");
		ret = -ENOMEM;
		goto error;	
	}

	/* now we are commited for this send! */
	
	test_pci_debug("cmd %d seq %llu\n", be16_to_cpu(cmd->op), ctx->ring_seq);
	

	ring_cmd = &ctx->cmd_ring[ctx->ring_head];
	ring_event = &ctx->event_ring[ctx->ring_head];

	memset(ring_event, 0, sizeof(*ring_event));

	/* populate the command */
	*ring_cmd = *cmd;

	/* command & matching event must have same seq number */
	ring_cmd->seq = cpu_to_be64(ctx->ring_seq);

	sg_init_one(&event_sg, ring_event, sizeof(*ring_event));
	sg_init_one(&cmd_sg, ring_cmd, sizeof(*ring_cmd));

	/* send the buffers to the hw. event is sent first! */
	ret = virtqueue_add_inbuf(ctx->vq_event, &event_sg, 1, event, GFP_KERNEL);
	if (ret) {
		test_pci_debug("event post failed! err %d\n", ret);
		goto error;
	}
	if (!virtqueue_kick(ctx->vq_event)) {
		test_pci_debug("event kick failed!\n");
		ret = -EIO;
		goto error;
	}

	ret = virtqueue_add_outbuf(ctx->vq_cmd, &cmd_sg, 1, ctx, GFP_KERNEL);
	if (ret) {
		test_pci_debug("cmd post failed! err %d\n", ret);
		goto error;
	}
	if (!virtqueue_kick(ctx->vq_cmd)) {
		test_pci_debug("cmd kick failed!\n");
		ret = -EIO;
		goto error;
	}

	ret = virttestpci_wait_for_cmd_complete(ctx);

	if (ret) {
		test_pci_debug("wait for cmd failed! err %d\n", ret);
		goto error;
	}

	if (event)
		*event = *ring_event; 

	ctx->ring_head = ring_inc(ctx->ring_head);
	ctx->ring_seq++;

error:
	mutex_unlock(&virttestpci_vq_lock);
	return ret;
}

static void virttestpci_del_vqs(struct virtio_device *vdev)
{
	test_pci_debug("enter\n");
	/* Now we reset the device so we can clean up the queues. */
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);
}

static void virttestpci_vq_cmd_cb(struct virtqueue *vq)
{
	struct virttestpci_ctx* ctx = vq->vdev->priv;
	test_pci_debug("enter ctx %p vq %s\n", ctx, vq->name);
	wake_up(&ctx->cmd_acked);
}

static void virttestpci_vq_event_cb(struct virtqueue *vq)
{
	struct virttestpci_ctx* ctx = vq->vdev->priv;
	test_pci_debug("enter ctx %p vq %s\n", ctx, vq->name);
	wake_up(&ctx->event_acked);
}

/* test pci char device file operations */
static int virttestpci_open(struct inode *inode, struct file *file)
{
	test_pci_debug("enter\n");
	if (!dev_ctx) {
		test_pci_debug("null dev_ctx!\n");
		return -EINVAL;
	}
        file->private_data = dev_ctx;
	return 0;
}

static int virttestpci_close(struct inode *inode, struct file *file)
{
	test_pci_debug("enter\n");
	/* noting to free */
	return 0;
}

static ssize_t virttestpci_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_ops)
{
	/* we do not support write yet */
	return -EINVAL;
}

static ssize_t virttestpci_read(struct file *filp, char __user *buf, size_t count, loff_t *f_ops)
{
	/* we do not support read yet */
	return -EINVAL;
}

static loff_t virttestpci_llseek(struct file *filp, loff_t off, int whence)
{
	/* we do not support llsek yet */
	return -EINVAL;
}

static long virttestpci_uioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	//struct virttestpci_ioctl_data *data =
	//	(struct virttestpci_ioctl_data *)arg;
	struct virttrstpci_cmd pci_cmd = {0};
	struct virttrstpci_event pci_event = {0};
	struct virttestpci_ctx *ctx = filp->private_data;
	int ret = 0;

	test_pci_debug("enter cmd 0x%x\n", cmd);

	switch (cmd)
	{
	case VIRTTESTPCI_IOCTL_DEV_PING:
		pci_cmd.op = cpu_to_be16(VIRTTESTPCI_OP_DEV_PING);
		ret = virttestpci_post_cmd(ctx, &pci_cmd, &pci_event);
		break;
	default:
		test_pci_debug("unknown cmd 0x%x\n", cmd);
		return -EINVAL;
	}

	if (ret) {
		test_pci_debug("error cmd failed! err %d\n", ret);
		return ret;
	}

	/* got hw event */
	test_pci_debug("hw event! op %d seq %lld status %d\n",
		be16_to_cpu(pci_event.op), be64_to_cpu(pci_event.seq),
		be16_to_cpu(pci_event.status));

	return 0;
}

static struct file_operations test_pci_fops =
{
        .open		= virttestpci_open,
        .release	= virttestpci_close,
        .read		= virttestpci_read,
        .write		= virttestpci_write,
        .llseek		= virttestpci_llseek,
        .unlocked_ioctl	= virttestpci_uioctl,
};

#define DRIVER_TEST_NAME "test_pci"
static dev_t test_pci_devt;
static int test_pci_devs_max = 1;
static unsigned int test_pci_major;
static unsigned int test_pci_minor;

static int virttestpci_probe(struct virtio_device *vdev)
{
	#define VIRTTESTPCI_NUM_VQS 	 (2)
	struct virtqueue		*vqs[VIRTTESTPCI_NUM_VQS];
	vq_callback_t			*callbacks[] = { virttestpci_vq_cmd_cb, virttestpci_vq_event_cb };
	static const char * const	 names[] = { "virttestpci_cmd", "virttestpci_event" };
	int				 err;

	test_pci_debug("enter\n");

	if (dev_ctx) {
		test_pci_debug("dev_ctx is not null! fail!\n");
		return -EINVAL;
	}

	BUILD_BUG_ON(ARRAY_SIZE(vqs) != ARRAY_SIZE(callbacks));
	BUILD_BUG_ON(ARRAY_SIZE(vqs) != ARRAY_SIZE(names));

	/* attach our device context to virtio device */
	vdev->priv = dev_ctx = kzalloc(sizeof(*dev_ctx), GFP_KERNEL);

	if (!dev_ctx) {
		test_pci_debug("failed to allocate dev_ctx!\n");
		return -EINVAL;
	}

	dev_ctx->vdev		= vdev;
	dev_ctx->ring_tail	= VIRTTESTPCI_RING_SIZE-1;
	dev_ctx->ring_seq	= VIRTTESTPCI_RING_SIZE; /* like index 0 in ring */

	atomic_set(&dev_ctx->stop, 0);

	init_waitqueue_head(&dev_ctx->cmd_acked);
	init_waitqueue_head(&dev_ctx->event_acked);

	/* find the virtio hw queues */
	err = vdev->config->find_vqs(vdev, VIRTTESTPCI_NUM_VQS, vqs,
				     callbacks, names);

	if (err) {
		test_pci_debug("failed to find vqs! err %d\n", err);
		return err;
	}

	dev_ctx->vq_cmd		= vqs[0];
	dev_ctx->vq_event	= vqs[1];

	/* initialize the char device */
	err = alloc_chrdev_region(&test_pci_devt, test_pci_minor,
				  test_pci_devs_max, DRIVER_TEST_NAME);
	if (err) {
		test_pci_debug("failed to alloc chardev region! err %d\n", err);
		return err;
	}
	test_pci_major = MAJOR(test_pci_devt);
	dev_ctx->cdev = (struct cdev*)kzalloc(sizeof(struct cdev), GFP_KERNEL);
	cdev_init(dev_ctx->cdev, &test_pci_fops);
	dev_ctx->cdev->owner = THIS_MODULE;
	err = cdev_add(dev_ctx->cdev, test_pci_devt, test_pci_devs_max);
	if (err) {
		test_pci_debug("failed to add cdev! err %d\n", err);
		return err;
	}
	test_pci_debug("%s driver(major %d) installed.\n", DRIVER_TEST_NAME, test_pci_major);

	test_pci_debug("initialized %d vq\n", VIRTTESTPCI_NUM_VQS);

	virtio_device_ready(vdev);
	return 0;
}

static void virttestpci_changed(struct virtio_device *vdev)
{
	test_pci_debug("enter\n");
}

static void virttestpci_stop_cmd_process(struct virttestpci_ctx *ctx)
{
	test_pci_debug("enter\n");
	/* stop the command & event processing */
	atomic_set(&ctx->stop, 1);
	/* wake command processing threads */
	wake_up(&ctx->cmd_acked);
	wake_up(&ctx->event_acked);
	/* wait for threads to complete */
	mutex_lock(&virttestpci_vq_lock);
	mutex_unlock(&virttestpci_vq_lock);
	test_pci_debug("command wait stopped...\n");
}

static void virttestpci_remove(struct virtio_device *vdev)
{
	struct virttestpci_ctx*	ctx = vdev->priv;

	test_pci_debug("enter\n");

	cdev_del(ctx->cdev);
        unregister_chrdev_region(test_pci_devt, test_pci_devs_max);

	dev_ctx = NULL;
	virttestpci_stop_cmd_process(ctx);
	virttestpci_del_vqs(vdev);
	ctx = vdev->priv;
	vdev->priv = NULL;
	kfree(ctx);
}

#ifdef CONFIG_PM_SLEEP
static int virttestpci_freeze(struct virtio_device *vdev)
{
	test_pci_debug("enter\n");
	return 0;
}

static int virttestpci_restore(struct virtio_device *vdev)
{
	test_pci_debug("enter\n");
	virtio_device_ready(vdev);
	return 0;
}
#endif

static unsigned int features[] = {
};

static struct virtio_driver virtio_test_pci_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	virttestpci_probe,
	.remove =	virttestpci_remove,
	.config_changed = virttestpci_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze	=	virttestpci_freeze,
	.restore =	virttestpci_restore,
#endif
};

module_virtio_driver(virtio_test_pci_driver);
MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio test_pci driver");
MODULE_LICENSE("GPL");
