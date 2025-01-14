//
// Created by de29664 on 11/21/23.
//

#ifndef LINUX_HAKC_LEAK_IN_H
#define LINUX_HAKC_LEAK_IN_H

#ifdef CONFIG_HAKC_DEMO_LEAK
#define HAKC_LEAK_IN

#define PROC_WRITE_BODY                                                                                     \
    ssize_t ret;                                                                                            \
    printk("HAKC_LEAK_IN procfile_write called\n");                                                         \
    ret = simple_write_to_buffer((void*)&_hakc_ptr, sizeof(_hakc_ptr), offset, buf, buf_len);               \
	if (*offset == sizeof(_hakc_ptr))                                                                       \
		printk("GOT LEAKED PTR: %p\n", _hakc_ptr);                                                          \
	return ret                                                                                              \

#endif

#include "hakc-demo-leak.h"

#endif //LINUX_HAKC_LEAK_IN_H
