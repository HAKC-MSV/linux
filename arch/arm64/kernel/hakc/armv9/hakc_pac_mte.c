#include <linux/hakc/hakc.h>
#include <asm/mte.h>
#include <asm/mte-kasan.h>
#include <asm/memory.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <uapi/linux/netlink.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

void mte_enable_kernel_sync(void);

struct percpu_info {
	void *signed_addr;
	bool is_percpu, is_dynamic;
	void *percpu_addr;
};

volatile bool mte_global_debug = false;
EXPORT_SYMBOL(mte_global_debug);

extern bool hakc_initialized;
void hakc_init_tags(void)
{
	pr_info("Initializing tags for HAKC\n");

	/* Enable MTE Sync Mode for EL1. */
	mte_enable_kernel_sync();

	hakc_initialized = true;
	isb();
}

void hakc_color_address(const void *addr_to_color, clique_color_t color,
			size_t size)
{
	void *ptr;
	void *safe_addr_to_color;
	if (!addr_to_color) {
		return;
	}
	if (!hakc_initialized) {
		return;
	}
	if (!VALID_COLOR(color)) {
		color = SILVER_CLIQUE;
	}
	safe_addr_to_color = (void*)HAKC_GET_SAFE_PTR(addr_to_color);
	ptr = (void *)HAKC_GET_SAFE_PTR(addr_to_color);
	ptr = (void *)round_down((unsigned long)ptr, COLOR_GRANULARITY);

	if (size > COLOR_GRANULARITY) {
		size = round_up(size + (safe_addr_to_color - ptr),
				COLOR_GRANULARITY);
	} else {
		size = COLOR_GRANULARITY;
	}

	HAKC_INFO("Coloring %u bytes at 0x%lx %s (%d)\n", size, ptr,
			get_hakc_color_name(color), color);

	mte_set_mem_tag_range(ptr, size, (u8)color, false);

	HAKC_INFO("%lx is colored %s (%s)\n", safe_addr_to_color,
			get_hakc_color_name(
				get_hakc_address_color(safe_addr_to_color)),
			get_hakc_color_name(color));
}
EXPORT_SYMBOL(hakc_color_address);

static inline clique_color_t _get_mte_tag(const void *addr)
{
	return (clique_color_t)mte_get_mem_tag((void *)addr);
}

clique_color_t get_hakc_address_color(const void *addr)
{
	unsigned long _addr = (unsigned long)addr;
	clique_color_t color;
	/*
	 * The kernel will return (unsigned short)-1 for pointer values, so
	 * ignore those, or error pointers
	 */
	if (_addr <= 0xffffffff) {
		HAKC_ERR("get_hakc_address_color\n");
		HAKC_ERR("\t_addr <= 0xffffffff (0x%lx)\n", _addr);
		return SILVER_CLIQUE;
	} else if (is_userspace_addr(addr)) {
		HAKC_ERR("get_hakc_address_color\n");
		HAKC_ERR("\tis_userspace_addr(addr) (0x%lx)\n", (void*)addr);
		return SILVER_CLIQUE;
	} else if (!hakc_initialized) {
		HAKC_INFO("!hakc_initialized\n");
		return SILVER_CLIQUE;
	}

	if (addr_is_signed(addr)) {
		_addr = (unsigned long)HAKC_KADDR(addr);
	}

	color = _get_mte_tag((void *)_addr);
	HAKC_INFO("get_hakc_address_color: %llx is colored %s\n",
			addr, get_hakc_color_name(color));
	return color;
}
EXPORT_SYMBOL(get_hakc_address_color);

void *sign_data(const void *address, pac_salt_t modifier)
{
	void *result;
	HAKC_INFO("Signing data pointer %lx with salt %lx\n", address,
			modifier);

	asm(
		/*
		 * using pacia instead of pacda
		 * because AD keys can change during context switch
		 */
		".arch_extension pauth\n"
		"pacia %[addr], %[mod]"
		: "=r"(result)
		: [addr] "0"(address), [mod] "r"(modifier)
		:);

	HAKC_INFO("sign data result is %llx\n", result);

	return result;
}

void *sign_code(const void *address, pac_salt_t modifier)
{
	void *result;
	HAKC_INFO("Signing code pointer %lx with salt %lx\n", address,
			modifier);

	asm(
		".arch_extension pauth\n"
		"pacia %[addr], %[mod]"
		: "=r"(result)
		: [addr] "0"(address), [mod] "r"(modifier)
		:);
	return result;
}

void *hakc_auth_data_ptr(const void *address, pac_salt_t modifier)
{
	void *result;
	HAKC_INFO("Authenticating data at %lx with salt %lx\n", address,
			modifier);

	asm(
		/*
		 * using autia instead of autda
		 * because AD keys can change during context switch */
		".arch_extension pauth\n"
		"autia %[addr], %[mod]"
		: "=r"(result)
		: [addr] "0"(address), [mod] "r"(modifier)
		:);

	HAKC_INFO("auth data result is %llx\n", result);

	if (HAKC_DEBUG && mte_global_debug) {
		pr_info("result: %lx\n", result);
	}

	/*
	 * Working around Tagged Address API / TBI
	 *
	 * auth failed if not a valid kernel pointer at this point
	 * make next deref fail even with TBI enabled
	 * invalidp_........  -> 0xff12...._........
	 * in QEMU emulation, failed aut pointers are 0xbfff...._........
	 */
	if (((uintptr_t)result & 0xffff000000000000) != 0xffff000000000000)
		result = (void*)(0xff12000000000000 |
				((uintptr_t)result & 0x0000ffffffffffff));

	return result;
}

void *hakc_auth_code_ptr(const void *address, pac_salt_t modifier)
{
	void *result;
	HAKC_INFO("Authenticating code at %lx with salt %lx\n", address,
			modifier);

	asm(
		".arch_extension pauth\n"
		"autia %[addr], %[mod]"
		: "=r"(result)
		: [addr] "0"(address), [mod] "r"(modifier)
		:);

	/*
	 * auth failed if not a valid kernel pointer at this point
	 * make next deref fail even with TBI enabled
	 * invalidp_........  -> 0xff12...._........
	 * in QEMU emulation, failed aut pointers are 0xbfff...._........
	 */
	if (((uintptr_t)result & 0xffff000000000000) != 0xffff000000000000)
		result = (void*)(0xff12000000000000 |
				((uintptr_t)result & 0x0000ffffffffffff));

	return result;
}

bool is_readonly(unsigned long addr)
{
	pte_t *pte;
	/*
	 * TODO: Figure out why pte_write sometimes returns true when the
	 * page is read-only
	 */
	if (is_kernel_rodata(addr)) {
		return true;
	} else if(addr >= 0xfffffdfffe5f9000) {
		/*
		 * HACK: This address is the start of the fixed mappings
		 * regions according to the memory layout for ARM64
		 */
		return true;
	} else if(is_kernel_text(addr)) {
		return true;
	}
	pte = virt_to_kpte(addr);
	return pte_present(*pte) && !pte_write(*pte);
}
