//
// Created by de29664 on 11/21/23.
//

#ifndef LINUX_HAKC_LEAK_OUT_H
#define LINUX_HAKC_LEAK_OUT_H

#ifdef CONFIG_HAKC_DEMO_LEAK
#define HAKC_LEAK_OUT

#define PROC_READ_BODY                                                                                          \
    printk("HAKC_LEAK_OUT procfile_read called\n");                                                             \
	if ( !_hakc_ptr )                                                                                           \
		return -EAGAIN;                                                                                         \
    return simple_read_from_buffer(buf, buf_len, offset, (void*)&_hakc_ptr, sizeof(_hakc_ptr))                  \


#endif

#include "hakc-demo-leak.h"

#endif //LINUX_HAKC_LEAK_OUT_H
