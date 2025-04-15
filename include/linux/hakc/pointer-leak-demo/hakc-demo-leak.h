/* Docs:
 * All modules involved in leaking should use CREATE_PROC() and
 * CLEANUP_PROC() in module_init and module_exit, respectively.
 * These require the name for the file in /proc/ and this argument
 * should be the same for both.
 *
 * Both modules should use the SETUP_HAKC_LEAK() in the body of their module,
 * not in a function. It is also required to add `#define HACK_LEAK_IN` or
 * `#define HACK_LEAK_OUT above` the include for this header.
 *
 * The leaker module should use SET_HAKC_LEAK_PTR() with the argument being
 * a local pointer that will be seen in the /proc/ file.
 *
 * The module that will write to this pointer should use HAKC_LEAK_PTR_SET()
 * to check if the pointer is valid, and USE_HAKC_LEAK_PTR() with the argument
 * set to a local pointer that will copy the leak from the /proc/ file.
 */

#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */
#include <linux/fs.h>

typedef uintptr_t proc_ptr_t;

#ifdef CONFIG_HAKC_DEMO_LEAK
#if defined(HAKC_LEAK_OUT) & defined (HAKC_LEAK_IN)
#error "Cannot have both HAKC_LEAK_IN and HAKC_LEAK_OUT defined"
#endif /* HAKC_LEAK_OUT & HAKC_LEAK_IN */

#if !defined(HAKC_LEAK_OUT) & !defined(HAKC_LEAK_IN)
#error "Neither HAKC_LEAK_OUT nor HAKC_LEAK_IN is defined"
#endif

/**
 * This function is called then the /proc file is read
 *
 */
static ssize_t procfile_read(struct file *f, char __user *buf,\
		      size_t buf_len, loff_t *offset);

/**
 * This function is called with the /proc file is written
 *
 */
static ssize_t procfile_write(struct file *file, const char __user *buf,
		   size_t buf_len, loff_t *offset);

#define PROC_DEFAULT_BODY   return -EINVAL

#ifndef PROC_READ_BODY
#define PROC_READ_BODY      PROC_DEFAULT_BODY
#endif

#ifndef PROC_WRITE_BODY
#define PROC_WRITE_BODY     PROC_DEFAULT_BODY
#endif

#define SETUP_HAKC_LEAK()                                                       \
static struct proc_dir_entry *pde;                                              \
static volatile proc_ptr_t _hakc_ptr = 0;                                       \
static ssize_t procfile_read(struct file *f, char __user *buf,                  \
		      size_t buf_len, loff_t *offset) {                                 \
    PROC_READ_BODY;                                                             \
}                                                                               \
static ssize_t procfile_write(struct file *file, const char __user *buf,        \
		   size_t buf_len, loff_t *offset) {                                    \
    PROC_WRITE_BODY;                                                            \
}                                                                               \
static const struct proc_ops pops = {                                           \
    .proc_read	= procfile_read,                                                \
    .proc_write	= procfile_write,                                               \
    .proc_lseek = no_llseek,                                                    \
}

/* Setting functions */

#define HAKC_LEAK_PTR_SET() (_hakc_ptr != 0)

#ifdef HAKC_LEAK_IN /* HAKC_LEAK_IN (SET/USE) */

#define USE_HAKC_LEAK_PTR(_ptr_name)\
	_ptr_name = (typeof(_ptr_name)) _hakc_ptr

#else /* !HAKC_LEAK_IN (SET/USE) */

#define SET_HAKC_LEAK_PTR(_ptr_name)\
	_hakc_ptr = (proc_ptr_t) _ptr_name

#endif /* HAKC_LEAK_IN (SET/USE) */

/*
 * This should be run in module_init
 */
#define CREATE_PROC(_name)                                                      \
    do {                                                                        \
        pde = proc_create(_name, 0600, NULL, &pops);                            \
        if (!pde) {                                                             \
            printk(KERN_ERR "Unable to make /proc/%s", _name);                  \
        } else {                                                                \
            proc_set_size(pde, sizeof(uintptr_t));                              \
            printk(KERN_INFO "/proc/%s created for pointer size %d.\n",         \
                   _name, sizeof(proc_ptr_t));                                  \
        }                                                                       \
    } while(0)

/*
 * This should be run in module_exit
 */
#define CLEANUP_PROC(_name)                                                     \
    do{                                                                         \
	    remove_proc_entry(_name, NULL);                                         \
	    printk(KERN_INFO "/proc/%s removed.\n", _name);                         \
    } while(0)

#else /* !CONFIG_HAKC_DEMO_LEAK */

#define MSG "CONFIG_HAKC_DEMO_LEAK disabled"

#define SETUP_HAKC_LEAK()

#define SET_HAKC_LEAK_PTR(_ptr_name)

#define HAKC_LEAK_PTR_SET() false

#define USE_HAKC_LEAK_PTR(_ptr_name)

#define CREATE_PROC(_name)\
	printk(KERN_INFO MSG ", not creating /proc/%s device.\n", _name);

#define CLEANUP_PROC(_name)\
	printk(KERN_INFO MSG ", not deleting /proc/%s device.\n", _name);

#endif /* CONFIG_HAKC_DEMO_LEAK */
