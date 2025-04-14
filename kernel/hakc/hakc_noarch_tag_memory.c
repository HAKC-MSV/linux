#include <linux/hakc/hakc.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <uapi/linux/netlink.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>

#define TAGS_PER_BYTE 2

struct percpu_info {
	void *signed_addr;
	bool is_percpu, is_dynamic;
	void *percpu_addr;
};

static size_t tagpool_physical_size;
static uint8_t *tagpool_physical;

extern bool hakc_initialized;
void hakc_init_tags(void)
{
	/* initialize a byte value with two 4-bit SILVER tags for memset */
	uint8_t fill_color = (SILVER_CLIQUE - START_CLIQUE) & 0xf;
	fill_color |= (fill_color << 8);

	/* guard against multiple init */
	if (hakc_initialized) return;

	/*
	 * here we calculate the total physical memory
	 * without subtracting memory holes or reserved ranges
	 */
	tagpool_physical_size = (size_t)((get_num_physpages() * PAGE_SIZE) /
					(COLOR_GRANULARITY * TAGS_PER_BYTE));

	pr_info("Initializing tags for HAKC: physical memory tagpool size "
		"%lx bytes\n",
		tagpool_physical_size);

	tagpool_physical = (uint8_t *)__vmalloc(tagpool_physical_size,
						GFP_KERNEL);
	if (!tagpool_physical) {
		pr_err("Could not allocate physical memory tagpool. "
			"HAKC is disabled.\n");
		return;
	}

	pr_info("HAKC physical tagpool allocated at vma %p\n",
		tagpool_physical);

	/* everything is tagged SILVER_CLIQUE by default */
	memset(tagpool_physical, fill_color, tagpool_physical_size);

	hakc_initialized = true;
}

#define PTE_MASK 0x0000fffffffff000
#define X86_MEMSTART ((uintptr_t)0x100000000)
#define X86_DIRECT_MAP_START 0xffff888000000000
#define X86_DIRECT_MAP_END 0xffffc88000000000

/* page table walk for platforms using 48-bit VA/PA with 4KB pages */
uintptr_t hakc_pagetable_walk(const void *addr)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;
	pte_t pte;

	unsigned long vaddr = (unsigned long)addr;

#if IS_ENABLED(CONFIG_HAKC_X86)
	/* https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt */
	/* ffff888000000000 direct mapping of all physical memory */
	/* this is an optimization */
	if (vaddr >= X86_DIRECT_MAP_START && vaddr < X86_DIRECT_MAP_END) {
		return vaddr - X86_DIRECT_MAP_START - X86_MEMSTART;
	}
#endif

	pgdp = pgd_offset(&init_mm, vaddr);
	if (pgd_none(*pgdp) || pgd_bad(*pgdp)) {
		pr_err("none or bad pgd\n");
		return (uintptr_t)0;
	}

	p4dp = p4d_offset(pgdp, vaddr);
	if (p4d_none(*p4dp) || p4d_bad(*p4dp)) {
		pr_err("none or bad p4d\n");
		return (uintptr_t)0;
	}

	pudp = pud_offset(p4dp, vaddr);
	if (pud_none(*pudp) || pud_bad(*pudp)) {
		pr_err("none or bad pud\n");
		return (uintptr_t)0;
	}

	pmdp = pmd_offset(pudp, vaddr);
	if (pmd_none(*pmdp) || pmd_bad(*pmdp)) {
		pr_err("none or bad pmd\n");
		return (uintptr_t)0;
	}

	ptep = pte_offset_kernel(pmdp, vaddr);
	pte = *ptep;
	if (!ptep) {
		pr_err("none or bad pte\n");
		return (uintptr_t)0;
	}

#if IS_ENABLED(CONFIG_HAKC_ARM_V8)
	return (((uintptr_t)pte_val(pte) & (uintptr_t)(PTE_MASK & PAGE_MASK)) |
		(((uintptr_t)addr) & (PAGE_SIZE-1))) - (uintptr_t)memstart_addr;
#endif

#if IS_ENABLED(CONFIG_HAKC_X86)
	/*
	 * so far I've seen memory mapped to physical address space starting at:
	 * 0x1_00000000 in VirtualBox, QEMU and documentation
	 * going with that until this breaks
	 */
	return (((uintptr_t)pte_val(pte) & (uintptr_t)(PTE_MASK & PAGE_MASK)) |
		(((uintptr_t)addr) & (PAGE_SIZE-1))) - X86_MEMSTART;
#endif
}

#define COLOR_DEBUG 0

void hakc_color_address(const void *addr_to_color, clique_color_t color,
			size_t size)
{
	void *ptr;
	void *safe_addr_to_color;
	size_t coloring_size;
#if HAKC_USE_SYMBOLS && IS_ENABLED(CONFIG_KALLSYMS)
	char name[KSYM_SYMBOL_LEN];
#endif

	uint8_t tag;
	uintptr_t next_granule;
	size_t granules_to_tag;
	size_t full_byte_granules;

	if (SILVER_CLIQUE == color) {
		return;
	}

	if (!hakc_initialized) {
		return;
	}
	if (!addr_to_color) {
		return;
	}
	if (!VALID_COLOR(color)) {
		HAKC_INFO("%p !VALID_COLOR(%x)\n", addr_to_color, color);
		color = SILVER_CLIQUE;
	}

	safe_addr_to_color = (void*)HAKC_GET_SAFE_PTR(addr_to_color);
	ptr = (void *)HAKC_GET_SAFE_PTR(addr_to_color);
	ptr = (void *)round_down((unsigned long)ptr, COLOR_GRANULARITY);

	if (size > COLOR_GRANULARITY) {
		coloring_size = round_up(size + (safe_addr_to_color - ptr),
					COLOR_GRANULARITY);
	} else {
		coloring_size = COLOR_GRANULARITY;
	}

#if HAKC_USE_SYMBOLS && IS_ENABLED(CONFIG_KALLSYMS)
	sprint_symbol(name, _RET_IP_);
	HAKC_INFO("hakc_color_address called from %lx (%s)\n", _RET_IP_, name);
#endif

	HAKC_INFO("Coloring %zu bytes at %p %s (%d)\n", coloring_size, ptr,
		 get_hakc_color_name(color), color);

	/*
	 * each byte in tagpool_physical stores 2 tags (2 consecutive granules)
	 * use memset as much as possible to set tags
	 * there is the case that the first granule to be tagged
	 * would be the second nibble of a tag-storage byte
	 * in that case, set it separately
	 * then memset (int)((total_granules - 1) / 2) bytes with the value
	 * (tag << 4) | (tag)
	 * finally if there is a remaining granule to be tagged
	 * it is the first nibble of the the tag-store byte,
	 * set it
	 */
	tag = (color - START_CLIQUE) & 0xf;

	/* address translation */
	uintptr_t paddr = hakc_pagetable_walk(ptr);
	if (paddr == 0) {
		HAKC_INFO("Can't translate address to color %p\n", ptr);
		return;
	}

	next_granule = hakc_pagetable_walk(ptr) >> 4;
	granules_to_tag = coloring_size / COLOR_GRANULARITY;

#if COLOR_DEBUG
	HAKC_INFO("setting color says address 0x%lx converts to granule 0x%lx "
			"of 0x%lx\n", ptr, next_granule, tagpool_physical_size);
	HAKC_INFO("\trange to color is: [0x%lx,0x%lx)\n", next_granule,
			next_granule + granules_to_tag);
#endif
	if (next_granule & 1) {
		uint8_t original_tagpool_byte;
		original_tagpool_byte = tagpool_physical[next_granule / 2];
		tagpool_physical[next_granule / 2] =
			(original_tagpool_byte & 0xf0) | tag;
		next_granule++;
		granules_to_tag--;
	}

	full_byte_granules = granules_to_tag / 2;

	if (full_byte_granules) {
		memset((void*)&tagpool_physical[next_granule / 2],
			(tag << 4) | tag, full_byte_granules);
		next_granule += full_byte_granules * 2;
		granules_to_tag -= full_byte_granules * 2;
	}

	/*
	 * one granule remaining
	 * this is always be the first nibble of the next tag byte
	 */
	if (granules_to_tag) {
		uint8_t original_tagpool_byte;

		original_tagpool_byte = tagpool_physical[next_granule / 2];
		tagpool_physical[next_granule / 2] =
			(original_tagpool_byte & 0xf) | (tag << 4);
	}

#if COLOR_DEBUG
	HAKC_INFO("%lx is colored %s and supposed to be colored %s\n",
			safe_addr_to_color,
			get_hakc_color_name(
				get_hakc_address_color(safe_addr_to_color)),
			get_hakc_color_name(color));
#endif
}
EXPORT_SYMBOL(hakc_color_address);

clique_color_t get_hakc_address_color(const void *addr)
{
	unsigned long _addr;
	uintptr_t granule;

	if (!hakc_initialized) {
		HAKC_INFO("!hakc_initialized\n");
		return SILVER_CLIQUE;
	}

	_addr = (unsigned long)((void*)HAKC_GET_SAFE_PTR(addr));

	/*
	 * The kernel will return (unsigned short)-1 for pointer values, so
	 * ignore those, or error pointers
	 */
	if (_addr <= 0xffffffff) {
		HAKC_ERR("get_hakc_address_color\n");
		HAKC_ERR("\t_addr <= 0xffffffff (0x%lx)\n", _addr);
		return SILVER_CLIQUE;
	} else if(is_userspace_addr(addr)) {
		HAKC_ERR("get_hakc_address_color\n");
		HAKC_ERR("\tis_userspace_addr(addr) (%p)\n", (void*)addr);
		return SILVER_CLIQUE;
	}

	/* address translation */
	granule = hakc_pagetable_walk((void*)HAKC_GET_SAFE_PTR(addr)) >> 4;
#if COLOR_DEBUG
	HAKC_INFO("get_color address 0x%lx converts to granule 0x%lx\n",
			addr, granule);
#endif
	return ((tagpool_physical[granule / 2] >>
			(4 * ((granule&1)==0))) & 0xf) + START_CLIQUE;
}
EXPORT_SYMBOL(get_hakc_address_color);
