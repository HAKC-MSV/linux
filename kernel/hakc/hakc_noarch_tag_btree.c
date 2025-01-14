#include <linux/hakc/hakc.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <uapi/linux/netlink.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

struct percpu_info {
	void *signed_addr;
	bool is_percpu, is_dynamic;
	void *percpu_addr;
};

struct tag_node {
	struct tag_node *left;
	struct tag_node *right;
	unsigned long safe_addr;
	unsigned long len;
	u8 color;
};

struct tag_node *insert(struct tag_node *root, unsigned long safe_addr,
			unsigned long len, u8 color)
{
	if (!root) {
		struct tag_node *new_tag_node =
			(struct tag_node *)kvmalloc(sizeof(struct tag_node),
							GFP_KERNEL);
		new_tag_node->safe_addr = safe_addr;
		new_tag_node->len = len;
		new_tag_node->color = color;
		new_tag_node->left = NULL;
		new_tag_node->right = NULL;
		return new_tag_node;
	} else if (safe_addr > root->safe_addr) {
		root->right = insert(root->right, safe_addr, len, color);
	} else if (safe_addr < root->safe_addr) {
		root->left = insert(root->left, safe_addr, len, color);
	} else if (safe_addr == root->safe_addr) {
		if (color != root->color) {
			root->color = color;
		}
		if (len != root->len) {
			root->len = len;
		}
	}
	return root;
}

u8 search(struct tag_node *root, unsigned long safe_addr)
{
	if (root == NULL) {
		return (u8)SILVER_CLIQUE;
	} else if ((root->safe_addr <= safe_addr) &&
			(safe_addr < (root->safe_addr + root->len))) {
		return root->color;
	} else if (root->safe_addr < safe_addr) {
		return search(root->right, safe_addr);
	} else {
		return search(root->left, safe_addr);
	}
}

static struct tag_node *root;

extern bool hakc_initialized;

void hakc_init_tags(void)
{
	pr_info("Initializing tags for HAKC\n");
	if (hakc_initialized) return;
	root = NULL;
	hakc_initialized = true;
}

void hakc_color_address(const void *addr_to_color, clique_color_t color,
			size_t size)
{
	void *ptr;
	void *safe_addr_to_color;
	/* do not re-color if it is going back to kernel */
	if (color == SILVER_CLIQUE) {
		return;
	}
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
	if (root == NULL) {
		root = insert(root, (unsigned long)ptr, size, color);
	} else {
		insert(root, (unsigned long)ptr, size, color);
	}
	HAKC_INFO("%lx is colored %s (%s)\n", safe_addr_to_color,
		 get_hakc_color_name(
			get_hakc_address_color(safe_addr_to_color)),
		 get_hakc_color_name(color));
}
EXPORT_SYMBOL(hakc_color_address);

clique_color_t get_hakc_address_color(const void *addr)
{
	unsigned long _addr = (unsigned long)addr;
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
	} else if  (!hakc_initialized) {
		HAKC_INFO("!hakc_initialized\n");
		return SILVER_CLIQUE;
	}

	_addr = (unsigned long)HAKC_KADDR(addr);

	return search(root, _addr);
}
EXPORT_SYMBOL(get_hakc_address_color);
