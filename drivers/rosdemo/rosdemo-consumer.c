#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/init.h> /* Needed for the macros */
#include <linux/kernel.h> /* Needed for pr_info() */
#include <linux/module.h> /* Needed by all modules */
#include <linux/cdev.h>

#if IS_BUILTIN(CONFIG_ROSDEMO)
#error "The ROS Demo should either be a loadable module or not compiled"
#endif

#define MY_MAJOR       508
#define MY_MAX_MINORS  4

static uintptr_t topicnameaddr;

struct my_device_data {
	struct cdev cdev;
};

static struct my_device_data devs[MY_MAX_MINORS];

ssize_t kernel_read(struct file *file,void *buf, size_t count, loff_t *pos);

static struct file *file_open(const char *path, int flags, int rights)
{
	struct file *filp = NULL;
	int err = 0;

	filp = filp_open(path, flags, rights);

	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		return NULL;
	}
	return filp;
}


static void file_close(struct file *file)
{
	filp_close(file, NULL);
}

static int my_open(struct inode *inode, struct file *file)
{
	static struct file* fd;
	static int open_count = 0;
	static char *tnfn = "/tmp/topicaddr";

	if (!open_count) {
		fd = file_open(tnfn, O_CREAT | O_RDONLY | O_APPEND, 0666);
		if (IS_ERR(fd)) {
			pr_info("ERROR ERROR ERROR ERROR ERROR\n");
			while(1) {};
		}

		kernel_read(fd, (void*)&topicnameaddr, sizeof(uintptr_t),
				&fd->f_pos);
		file_close(fd);

		pr_info("leaked topicnameaddr %0lx\n", topicnameaddr);

		((char *)((uintptr_t)topicnameaddr))[0] = 'U';
		((char *)((uintptr_t)topicnameaddr))[1] = 'H';
		((char *)((uintptr_t)topicnameaddr))[2] = 'O';
		((char *)((uintptr_t)topicnameaddr))[3] = 'H';

		open_count++;
	}
	return 0;
}


static ssize_t my_read(struct file *file, char __user *user_buffer, size_t size,
			loff_t *offset)
{
	if (size != 8) {
		return -1;
	} else if (copy_to_user(user_buffer, (char*)topicnameaddr, 8)) {
		return -EFAULT;
	}

	return 8;
}

static const struct file_operations my_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.read = my_read
};

static int __init rosdemo_consumer_init(void)
{
	int i, err;

	pr_info("Hello from ROSDEMO Consumer\n");

	err = register_chrdev_region(MKDEV(MY_MAJOR, 0), MY_MAX_MINORS,
					"rosdemo_consumer");
	if (err != 0) {
		/* report error */
		return err;
	}

	for (i = 0; i < MY_MAX_MINORS; i++) {
		/* initialize devs[i] fields */
		cdev_init(&devs[i].cdev, &my_fops);
		cdev_add(&devs[i].cdev, MKDEV(MY_MAJOR, i), 1);
	}

	return 0;
}

static void __exit rosdemo_consumer_exit(void)
{
	int i;
	pr_info("Goodbye from ROSDEMO Consumer\n");

	for (i = 0; i < MY_MAX_MINORS; i++) {
		/* release devs[i] fields */
		cdev_del(&devs[i].cdev);
	}
	unregister_chrdev_region(MKDEV(MY_MAJOR, 0), MY_MAX_MINORS);
}

module_init(rosdemo_consumer_init);
module_exit(rosdemo_consumer_exit);
MODULE_LICENSE("GPL");
