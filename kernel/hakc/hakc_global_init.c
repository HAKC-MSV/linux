//
// Created by de29664 on 5/9/24.
//

#include <linux/printk.h>
#include <linux/hakc/hakc-globals.h>

int hakc_init_globals(size_t num_initializers, hakc_global_init_fp hakc_global_inits[]) {
    unsigned int i;

    pr_info("HAKC Initializing %ld Globals", num_initializers);
    hakc_global_init_fp curr;
    for(i = 0; i < num_initializers; i++) {
        curr = hakc_global_inits[i];
        if(curr) {
            curr();
        }
    }

    return 0;
}

extern uintptr_t _s_hakc_init_global, _e_hakc_init_global;

int hakc_init_kernel_globals(void) {
    size_t num_globals = _e_hakc_init_global - _s_hakc_init_global;

    pr_info("%s called", __FUNCTION__);
    return hakc_init_globals(num_globals, (hakc_global_init_fp*)_s_hakc_init_global);
}
