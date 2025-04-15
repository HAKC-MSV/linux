#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <uapi/linux/netlink.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/tty.h>

/* Include last to allow proper def of "kernel_param" to be included above, if possible */
#include <linux/hakc/hakc.h>
#include <linux/hakc/hakc-globals.h>

#if IS_ENABLED(CONFIG_HAKC_ARM_V8) && IS_ENABLED(CONFIG_HAKC_ARM_V9)
#error "ARM v8 and ARM v9 HAKC configured together. Check .config and rebuild."
#endif

/* from mm/percpu.c, used to be exported */
#ifdef CONFIG_SMP
/* default addr <-> pcpu_ptr mapping, override in asm/percpu.h if necessary */
#ifndef __addr_to_pcpu_ptr
#define __addr_to_pcpu_ptr(addr)					\
	(void __percpu *)((unsigned long)(addr) -			\
			(unsigned long)pcpu_base_addr +			\
			(unsigned long)__per_cpu_start)
#endif
#ifndef __pcpu_ptr_to_addr
#define __pcpu_ptr_to_addr(ptr)						\
	(void __force *)((unsigned long)(ptr) +				\
			(unsigned long)pcpu_base_addr -			\
			(unsigned long)__per_cpu_start)
#endif
#else   /* CONFIG_SMP */
/* on UP, it's always identity mapped */
#define __addr_to_pcpu_ptr(addr)	(void __percpu *)(addr)
#define __pcpu_ptr_to_addr(ptr)		(void __force *)(ptr)
#endif  /* CONFIG_SMP */

/*
 * ARM v9 implements tagging and signing in one source:
 *  arch/arm64/kernel/hakc/armv9/hakc_pacmte.c
 *
 * ARM v8 / x86-64 implement tagging in:
 *  kernel/hakc/hakc_noarch_tag_btree.c
 *  kernel/hakc/hakc_noarch_tag_memory.c
 * ARM v8 / x86-64 implement signing in:
 *  arch/arm64/kernel/hakc/armv8/hakc_neon.c
 *  arch/x86/kernel/hakc/hakc_ni.c
 */

/* the following functions are dependent on tagging implementation */
extern void hakc_init_tags(void);
extern void hakc_color_address(const void *addr_to_color, clique_color_t color,
				size_t size);
extern clique_color_t get_hakc_address_color(const void *addr);
/* the following functions are dependent on signing implementation */
extern void *sign_data(const void *address, pac_salt_t modifier);
extern void *sign_code(const void *address, pac_salt_t modifier);
extern void *hakc_auth_data_ptr(const void *address, pac_salt_t modifier);
extern void *hakc_auth_code_ptr(const void *address, pac_salt_t modifier);

/* the following function is dependent on architecture */
extern bool is_readonly(unsigned long addr);

bool hakc_initialized = false;

struct percpu_info {
	void *signed_addr;
	bool is_percpu, is_dynamic;
	void *percpu_addr;
};

void initialize_hakc(void) {
    pr_info("Initializing HAKC system");
    hakc_init_tags();
    hakc_init_kernel_globals();
}

const char *get_hakc_color_name(clique_color_t color)
{
	switch (color) {
	case SILVER_CLIQUE:
		return "SILVER_CLIQUE";
	case GREEN_CLIQUE:
		return "GREEN_CLIQUE";
	case RED_CLIQUE:
		return "RED_CLIQUE";
	case ORANGE_CLIQUE:
		return "ORANGE_CLIQUE";
	case YELLOW_CLIQUE:
		return "YELLOW_CLIQUE";
	case PURPLE_CLIQUE:
		return "PURPLE_CLIQUE";
	case BLUE_CLIQUE:
		return "BLUE_CLIQUE";
	case GREY_CLIQUE:
		return "GREY_CLIQUE";
	case PINK_CLIQUE:
		return "PINK_CLIQUE";
	case BROWN_CLIQUE:
		return "BROWN_CLIQUE";
	case WHITE_CLIQUE:
		return "WHITE_CLIQUE";
	case BLACK_CLIQUE:
		return "BLACK_CLIQUE";
	case TEAL_CLIQUE:
		return "TEAL_CLIQUE";
	case VIOLET_CLIQUE:
		return "VIOLET_CLIQUE";
	case CRIMSON_CLIQUE:
		return "CRIMSON_CLIQUE";
	case GOLD_CLIQUE:
		return "GOLD_CLIQUE";
	default:
		return "INVALID_CLIQUE";
	}
}
EXPORT_SYMBOL(get_hakc_color_name);

static long long missed_accesses = 0;
static long long total_accesses = 0;
#if HAKC_LOG_FAILURE
static uintptr_t last_missed_address_sources[HAKC_MISSED_ADDR_COUNT];
static uint32_t last_missed_idx = 0;

static int hakc_show_counts(struct seq_file *m, void *v)
{
	seq_printf(m, "%lld %lld\n", missed_accesses, total_accesses);
	return 0;
}

static int hakc_counts_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hakc_show_counts, NULL);
}

static const struct proc_ops hakc_count_proc_ops = {
	.proc_open	= hakc_counts_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int hakc_show_missed_source_addresses(struct seq_file *m, void *v)
{
	uint32_t i;
	for (i = 0; i < ARRAY_SIZE(last_missed_address_sources); i++) {
#if IS_ENABLED(CONFIG_KALLSYMS)
		char name[KSYM_SYMBOL_LEN];
		sprint_symbol(name, last_missed_address_sources[i]);
		seq_printf(m, "0x%lx (%s)\n", last_missed_address_sources[i],
				name);
#else
		seq_printf(m, "0x%lx\n", last_missed_address_sources[i]);
#endif
	}
	return 0;
}

static int hakc_missed_source_addresses_proc_open(struct inode *inode,
							struct file* file)
{
	return single_open(file, hakc_show_missed_source_addresses, NULL);
}

static const struct proc_ops hakc_missed_src_proc_ops = {
	.proc_open 	= hakc_missed_source_addresses_proc_open,
	.proc_read 	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release 	= single_release,
};

static bool hakc_proc_entry_created = false;

int hakc_create_proc_entry(void)
{
	struct proc_dir_entry *proc_entry, *root;
	if (!hakc_proc_entry_created) {
		root = proc_mkdir("hakc", NULL);
		if (!root) {
			pr_warn("Failed to create HAKC root");
			return -ENOENT;
		}
		proc_entry = proc_create("counts", 0600, root,
						&hakc_count_proc_ops);
		if (!proc_entry) {
			pr_warn("Failed to register HAKC proc entry!");
			remove_proc_entry("hakc", NULL);
			return -ENOENT;
		}
		proc_entry = proc_create("miss-sources", 0600, root,
						&hakc_missed_src_proc_ops);
		if (!proc_entry) {
			pr_warn("Failed to register HAKC proc entry!");
			remove_proc_entry("counts", root);
			remove_proc_entry("hakc", NULL);
			return -ENOENT;
		}
		hakc_proc_entry_created = true;
	}
	return 0;
}
EXPORT_SYMBOL(hakc_create_proc_entry);
#endif

clique_color_t get_hakc_percpu_color(const void * __percpu addr)
{
	const void* _addr = raw_cpu_ptr(addr);
	return get_hakc_address_color(_addr);
}
EXPORT_SYMBOL(get_hakc_percpu_color);


static void *compute_pac(const void *addr, clique_color_t color,
				hakc_compartment_id_t compartment,
				void *(sign_func)(const void *, pac_salt_t))
{
	pac_salt_t modifier = PAC_MODIFIER(compartment,
						HAKC_MASK_COLOR(color));
	u64 ctx_addr = HAKC_CONTEXT_ADDR(addr);
	void *signed_ptr;

	signed_ptr = sign_func((const void *)ctx_addr, modifier);

	return (void *)((u64)signed_ptr | HAKC_COMPARTMENT_ADDR(addr));
}

static u64 compute_data_pac(const void *addr, clique_color_t color,
				hakc_compartment_id_t compartment)
{
	u64 result;
	result = (u64)compute_pac(addr, color, compartment, sign_data);
	return result;
}

static uintptr_t compute_code_pac(const void *addr, clique_color_t color,
					hakc_compartment_id_t compartment)
{
	u64 result;
	result = (u64)compute_pac(addr, color, compartment, sign_code);
	return result;
}

clique_color_t get_hakc_color_by_name(const char *color_name)
{
	clique_color_t color = START_CLIQUE;
	while (color != END_CLIQUE) {
		const char *curr_name = get_hakc_color_name(color);
		if (strcasecmp(color_name, curr_name) == 0) {
			break;
		}
		color++;
	}

	return color;
}
EXPORT_SYMBOL(get_hakc_color_by_name);

static inline bool verify_and_set_auth_ptr(uint64_t auth_ptr, void **ptr)
{
	bool result = !addr_is_signed((void *)auth_ptr);
	HAKC_INFO("%llx is%s authenticated\n", auth_ptr, result ? "" : " not");
	if (result && ptr) {
		*ptr = (void *)auth_ptr;
	} else if (!result && ptr) {
		if (HAKC_ALLOW) {
			*ptr = (void *)HAKC_GET_SAFE_PTR(auth_ptr);
		} else {
			*ptr = HAKC_INVALID_PTR;
			hakc_debug_breakpoint();
		}
	}
	return result;
}

static inline pac_salt_t create_pac_context(hakc_compartment_id_t compartment,
						u64 masked_color)
{
	return PAC_MODIFIER(compartment, masked_color);
}

static inline pac_salt_t obtain_modifier_cert(clique_color_t address_color,
						hakc_compartment_id_t compartment)
{
	pac_salt_t result;

	result = create_pac_context(compartment,
					HAKC_MASK_COLOR(address_color));
	return result;
}

static void *check_hakc_access(const void *address,
				hakc_compartment_id_t compartment,
				const clique_access_tok_t access_tok,
				void *(*auth_func)(const void *, pac_salt_t))
{
#if HAKC_USE_SYMBOLS && IS_ENABLED(CONFIG_KALLSYMS)
	char safename[KSYM_SYMBOL_LEN];
#endif
	pac_salt_t salt;
	unsigned long result;
	clique_color_t addr_color;
	void *safe_addr;

	if (!hakc_initialized) {
		HAKC_INFO("no check, !initialized");
		return (void*)HAKC_GET_SAFE_PTR(address);
	} else if (is_userspace_addr(address)) {
		HAKC_INFO("no check, userspace");
		return (void *)address;
	} else if (IS_ERR(address)) {
		HAKC_INFO("no check, ERR");
		return (void *)address;
	}

	total_accesses++;
	safe_addr = (void*)HAKC_GET_SAFE_PTR(address);

#if HAKC_USE_SYMBOLS && IS_ENABLED(CONFIG_KALLSYMS)
	sprint_symbol(safename, (uintptr_t)address);
	if (safename[0] == safename[1] == 'f') {
		HAKC_INFO("access_tok = 0x%llx\taddress = 0x%p\n", access_tok,
				address);
	} else {
		HAKC_INFO("access_tok = 0x%llx\taddress = 0x%p (%s)\n",
				access_tok, address, safename);
	}
#else
	HAKC_INFO("access_tok = 0x%lx\taddress = 0x%lx\n", access_tok,
		address);
#endif

	addr_color = get_hakc_address_color(safe_addr);
	HAKC_INFO("0x%p is colored %s and in compartment %u\n", address,
			get_hakc_color_name(addr_color), compartment);

	/*
	 * the address used to be masked with 0xFF000000_00000000
	 * this was causing the destruction of the PAC signature in
	 * the upper bits, and signed pointers would no longer authenticate
	 *
	 * this change fixes ARM v9 support and most importantly
	 * this change does not break ARM v8 or x86-64 support
	 */
	salt = obtain_modifier_cert(addr_color, compartment) & access_tok;
	HAKC_INFO("ctx_addr = %p salt = %llx\n", address, salt);
	result = (unsigned long)auth_func(
			(const void *)HAKC_CONTEXT_ADDR(address), salt);
	result |= (0x0000FFFFFFFFFFFF & (unsigned long)address);

	HAKC_INFO("result = %lx address = %p\n", result, address);
	if (HAKC_ALLOW) {
		if (addr_is_signed((void *)result)) {
			HAKC_INFO("Invalid pointer signature: 0x%p 0x%llx\n",
					address, salt);
			missed_accesses++;
#if HAKC_LOG_FAILURE
			last_missed_address_sources[last_missed_idx] =
				(uintptr_t)__builtin_return_address(0);
			last_missed_idx++;
			if (last_missed_idx >=
				ARRAY_SIZE(last_missed_address_sources)) {
				last_missed_idx = 0;
			}
#endif
		}
		result |= 0xFFFF000000000000;
	}

	return (void *)result;
}

static size_t hakc_get_valid_target_index(const void *target,
				const compartment_entry_tok_t *valid_targets,
				size_t n_targets)
{
	size_t i;
	size_t result = -1;
	clique_color_t target_color;
	pac_salt_t salt;
	u64 masked_color;

	target_color = get_hakc_address_color(target);
	masked_color = HAKC_MASK_COLOR(target_color);

	for (i = 0; i < n_targets; i++) {
		const compartment_entry_tok_t entry_token = valid_targets[i];
		salt = create_pac_context(entry_token.compartment,
						masked_color &
						entry_token.entry_token);
		if (verify_and_set_auth_ptr(
					(u64)hakc_auth_code_ptr(target, salt),
					NULL)) {
			result = i;
			break;
		}
	}

	return result;
}

void *check_hakc_data_access(const void *address,
				hakc_compartment_id_t compartment,
				const clique_access_tok_t access_tok)
{
#if HAKC_USE_SYMBOLS && IS_ENABLED(CONFIG_KALLSYMS)
	char name[KSYM_SYMBOL_LEN];
	sprint_symbol(name, _RET_IP_);
	HAKC_INFO("check_hakc_data_access called from %lx (%s)\n", _RET_IP_,
		name);
#endif

	if (!hakc_initialized) {
		return (void *)HAKC_GET_SAFE_PTR(address);
	}

	return check_hakc_access(address, compartment, access_tok,
					hakc_auth_data_ptr);
}
EXPORT_SYMBOL(check_hakc_data_access);

void *check_hakc_code_access(const void *address,
				hakc_compartment_id_t compartment,
				const clique_access_tok_t access_tok,
				const compartment_entry_tok_t *valid_targets,
				size_t n_targets)
{
	void *authenticated_ptr = NULL;
	size_t index;

	if (!hakc_initialized) {
		return (void *)HAKC_GET_SAFE_PTR(address);
	}

	HAKC_INFO("Checking code access to %p for %ld targets\n", address,
			n_targets);

	authenticated_ptr = check_hakc_access(address, compartment, access_tok,
						hakc_auth_code_ptr);

	if (addr_is_signed(authenticated_ptr) && n_targets > 0) {
		index = hakc_get_valid_target_index(address, valid_targets,
							n_targets) >= 0;

		HAKC_INFO("Code access to %p is%s allowed\n", address,
				(index > 0) ? "" : " not");

		if (index < 0) {
			authenticated_ptr = (void *)address;
		} else {
			authenticated_ptr = (void *)HAKC_GET_SAFE_PTR(address);
		}
	}

	return authenticated_ptr;
}
EXPORT_SYMBOL(check_hakc_code_access);

noinline void hakc_debug_breakpoint(void)
{
	dump_stack();
}
EXPORT_SYMBOL(hakc_debug_breakpoint);

void *hakc_sign_pointer(void *addr, hakc_compartment_id_t compartment,
			clique_color_t color, bool is_code)
{
	if (compartment == 0 || !hakc_initialized) {
		return HAKC_GET_SAFE_PTR(addr);
	}

	if (VALID_COMPARTMENT(compartment)) {
		addr = HAKC_GET_SAFE_PTR(addr);
		HAKC_INFO("\tsafe ptr %p\n", addr);
		if (is_code) {
			addr = (void *)compute_code_pac((void *)addr, color,
							compartment);
		} else {
			addr = (void *)compute_data_pac((void *)addr, color,
							compartment);
		}
		HAKC_INFO("TRANSFER RESULT to %d %p\n", compartment, addr);
	}
	return (void *)addr;
}
EXPORT_SYMBOL(hakc_sign_pointer);

void *hakc_sign_pointer_with_color(void *addr,
					hakc_compartment_id_t compartment,
					bool is_code)
{
	if (!addr) {
		return addr;
	}
	if (compartment == 0 || !hakc_initialized) {
		return HAKC_GET_SAFE_PTR(addr);
	}

	return hakc_sign_pointer(addr, compartment,
				get_hakc_address_color(addr), is_code);
}
EXPORT_SYMBOL(hakc_sign_pointer_with_color);

void __percpu *hakc_sign_pcpu_pointer_with_color(void __percpu *pcpu_ptr_base,
						hakc_compartment_id_t compartment) {
	void *result, *pcpu_ptr, *signed_ptr;
	if (!pcpu_ptr_base || !hakc_initialized) {
		return pcpu_ptr_base;
	}
	if (compartment == 0) {
		return __addr_to_pcpu_ptr(
			HAKC_GET_SAFE_PTR(__pcpu_ptr_to_addr(pcpu_ptr_base)));
	}

	pcpu_ptr = __pcpu_ptr_to_addr(pcpu_ptr_base);
	signed_ptr = hakc_sign_pointer(pcpu_ptr, compartment,
					get_hakc_percpu_color(pcpu_ptr_base),
					false);
	result = __addr_to_pcpu_ptr(signed_ptr);
	return result;

}
EXPORT_SYMBOL(hakc_sign_pcpu_pointer_with_color);

static void *color_and_sign(void *data_to_transfer, size_t size,
				hakc_compartment_id_t compartment,
				clique_color_t color, bool is_code)
{
	if (compartment == 0 || !hakc_initialized) {
		return HAKC_GET_SAFE_PTR(data_to_transfer);
	}
	if (!is_userspace_addr(data_to_transfer) && size > 0) {
		unsigned long addr = (unsigned long)data_to_transfer;

		HAKC_INFO("Transferring %lu bytes at %p to compartment %d "
				"(%s)\n",
				size, data_to_transfer, compartment,
				get_hakc_color_name(color));

		if (addr_is_signed(data_to_transfer)) {
			addr = HAKC_GET_SAFE_PTR(addr);
		}

		if (hakc_initialized && !is_code && !is_readonly(addr)) {
			hakc_color_address((void *)addr, color, size);
		} else if (hakc_initialized) {
			color = get_hakc_address_color(data_to_transfer);
			HAKC_INFO("%lx is read-only and colored %s\n", addr,
					get_hakc_color_name(color));
		}

		return hakc_sign_pointer((void *)addr, compartment, color,
					is_code);
	} else {
		return data_to_transfer;
	}
}

void *hakc_transfer_percpu(void __percpu *pcpu_ptr_base, size_t size,
				hakc_compartment_id_t compartment,
				clique_color_t color)
{
	void *result;
	void *pcpu_ptr;
	void *signed_ptr;

	if (!hakc_initialized) {
		return pcpu_ptr_base;
	}

	HAKC_INFO("Transferring percpu variable %p with size %lx to %d and "
			"color %s\n",
			pcpu_ptr_base, size, compartment,
			get_hakc_color_name(color));

	pcpu_ptr = __pcpu_ptr_to_addr(pcpu_ptr_base);

	signed_ptr = color_and_sign(pcpu_ptr, size * nr_cpu_ids, compartment,
					color, false);

	result = __addr_to_pcpu_ptr(signed_ptr);

	HAKC_INFO("Transferred percpu variable %p: %p (%p %p)\n",
			pcpu_ptr_base, result, per_cpu_ptr(result, 0),
			check_hakc_data_access(per_cpu_ptr(result, 0), compartment,
				obtain_modifier_cert(color, compartment)));
	return result;
}

void *hakc_transfer_to_clique(void *data_to_transfer, size_t size,
				hakc_compartment_id_t compartment,
				clique_color_t color, bool is_code)
{
	void *res;
#if HAKC_USE_SYMBOLS && IS_ENABLED(CONFIG_KALLSYMS)
	char name[KSYM_SYMBOL_LEN];
	sprint_symbol(name, _RET_IP_);

	HAKC_INFO("hakc_transfer_to_clique called from %lx (%s)\n", _RET_IP_,
			name);
#endif
	if (compartment == 0 || !hakc_initialized) {
		return HAKC_GET_SAFE_PTR(data_to_transfer);
	}
	if (!data_to_transfer) {
		return data_to_transfer;
	}
	res = color_and_sign(data_to_transfer, size, compartment, color,
				is_code);
	return res;
}
EXPORT_SYMBOL(hakc_transfer_to_clique);

/* alloc_percpu allocates a memory region for each CPU and then returns a
 * value p such that p + __cpu_offset[CPU_INDEX] computes the actual memory
 * location. So color all the memory locations, and change p to p_ such that
 * p_ + __cpu_offset[CPU_INDEX] = signed(p)
 */
void * __percpu hakc_transfer_percpu_to_clique(void * __percpu original,
					size_t size,
					hakc_compartment_id_t compartment,
					clique_color_t color)
{
	return hakc_transfer_percpu(original, size, compartment, color);
}

EXPORT_SYMBOL(hakc_transfer_percpu_to_clique);

void *hakc_transfer_string(void *str, hakc_compartment_id_t compartment,
				clique_color_t color)
{
	return hakc_transfer_to_clique(str, strlen(str) + 1, compartment,
					color, false);
}
EXPORT_SYMBOL(hakc_transfer_string);

struct sk_buff *hakc_transfer_skb(struct sk_buff *skb,
					hakc_compartment_id_t compartment,
					clique_color_t color)
{
	size_t data_offset;

	skb = HAKC_GET_SAFE_PTR(skb);
	data_offset = HAKC_GET_SAFE_PTR(skb->data) -
			HAKC_GET_SAFE_PTR(skb->head);

	skb->head = hakc_transfer_to_clique(skb->head,
					skb->truesize -
					SKB_DATA_ALIGN(sizeof(struct sk_buff)),
					compartment, color, false);

	skb->data = skb->head + data_offset;

	skb = hakc_transfer_to_clique(skb, sizeof(*skb), compartment, color,
					false);

	return skb;
}
EXPORT_SYMBOL(hakc_transfer_skb);

#if 0
const struct nlattr * const *hakc_transfer_nla(
					const struct nlattr * const nla[],
					size_t size,
					hakc_compartment_id_t compartment,
					clique_color_t color)
{
	struct nlattr **new_nla = HAKC_GET_SAFE_PTR((struct nlattr **)nla);
	int i;
	for (i = 0; i < size; i++) {
		if(new_nla[i]) {
			new_nla[i] = hakc_transfer_to_clique(new_nla[i],
					HAKC_GET_SAFE_PTR(new_nla[i])->nla_len,
					compartment, color, false);
		}
	}
	return hakc_transfer_to_clique(new_nla, sizeof(struct nlattr *) * size,
					compartment, color, false);
}
EXPORT_SYMBOL(hakc_transfer_nla);
#endif

struct file *hakc_transfer_file_struct(struct file *filep,
					hakc_compartment_id_t compartment,
					clique_color_t color)
{
	struct file *safe_filep;
	struct tty_file_private *safe_private;
	/* null pointer or invalid file (-1) */
	if (!filep || ((uintptr_t)filep == 0xfffffffffffffffe)) {
		return filep;
	}

	safe_filep = HAKC_GET_SAFE_PTR(filep);

	if (safe_filep->private_data) {
		safe_private = HAKC_GET_SAFE_PTR(
			((struct tty_file_private *)safe_filep->private_data));
		if (safe_private->tty) {
			safe_private->tty = hakc_transfer_to_clique(
						safe_private->tty,
						sizeof(struct tty_struct),
						compartment, color, false);
		}
		safe_filep->private_data = hakc_transfer_to_clique(
						safe_private,
						sizeof(*safe_private),
						compartment, color, false);
	}

	return hakc_transfer_to_clique(safe_filep, sizeof(*safe_filep),
					compartment, color, false);
}
EXPORT_SYMBOL(hakc_transfer_file_struct);

struct socket *hakc_transfer_socket(struct socket *socket,
					hakc_compartment_id_t compartment,
					clique_color_t color)
{
	struct socket *safe_socket;
	struct proto_ops *safe_ops;

	if (!socket) {
		return socket;
	}

	safe_socket = HAKC_GET_SAFE_PTR(socket);

	if (safe_socket->ops) {
		safe_ops = HAKC_GET_SAFE_PTR(
				((struct proto_ops *)safe_socket->ops));
		safe_socket->ops = hakc_transfer_to_clique(safe_ops,
					sizeof(*safe_ops),
					compartment, color, false);
	}

	return hakc_transfer_to_clique(safe_socket, sizeof(*safe_socket),
				       compartment, color, false);
}
EXPORT_SYMBOL(hakc_transfer_socket);
