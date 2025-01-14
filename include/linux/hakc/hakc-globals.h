//
// Created by de29664 on 5/9/24.
//

#ifndef HAKC_HAKC_GLOBALS_H
#define HAKC_HAKC_GLOBALS_H

#include <linux/types.h>

typedef void (*hakc_global_init_fp)(void);

int hakc_init_globals(size_t num_initializers, hakc_global_init_fp *hakc_global_inits);

int hakc_init_kernel_globals(void);

#endif //HAKC_HAKC_GLOBALS_H
