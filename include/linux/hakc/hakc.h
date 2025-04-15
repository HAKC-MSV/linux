#ifndef LINUX_HAKC_HAKC_H
#define LINUX_HAKC_HAKC_H

#include <linux/compiler_types.h>
#include <linux/bits.h>

#ifndef kernel_param
#include <linux/moduleparam.h>
#endif

noinline void hakc_debug_breakpoint(void);

typedef u32 hakc_compartment_id_t;
typedef u64 pac_salt_t;
typedef u64 clique_access_tok_t;

#define hakc_noinline
#define __color 0
#define __claque_id 0

#define HAKC_COLOR_BIT_COUNT 4
#define CLAQUE_ID_BIT_COUNT (64 - HAKC_COLOR_BIT_COUNT)

#define VALID_COMPARTMENT(compartment)                                       \
	((compartment) > 0 && (compartment) < ((1ul << CLAQUE_ID_BIT_COUNT) - 1))

#if IS_ENABLED(CONFIG_HAKC)

#define HAKC_DEBUG IS_ENABLED(CONFIG_HAKC_DEBUG_PRINT)
#define HAKC_ALLOW IS_ENABLED(CONFIG_HAKC_ALLOW_FAILED)
#define HAKC_SIGN_PTR IS_ENABLED(CONFIG_HAKC_SIGN_PTR)
#define HAKC_LOG_FAILURE IS_ENABLED(CONFIG_HAKC_LOG_FAILURE)

#define HAKC_INVALID_PTR (void *)0xDEADBEEF
#define HAKC_MISSED_ADDR_COUNT 5

#define HAKC_INFO(fmt, ...)                                                    \
        if (HAKC_DEBUG) {                                                      \
                pr_info(fmt, ##__VA_ARGS__);                                   \
        }
#define HAKC_ERR(fmt, ...)                                                     \
        if (HAKC_DEBUG) {                                                      \
                pr_err(fmt, ##__VA_ARGS__);                                    \
	}

#define HAKC_USE_SYMBOLS 1

#if IS_ENABLED(CONFIG_HAKC_ARM_V8) || IS_ENABLED(CONFIG_HAKC_ARM_V9)
#include <asm/memory.h>

#define HAKC_VA_BITS VA_BITS
#else
#define HAKC_VA_BITS 48
#endif // IS_ENABLED(CONFIG_HAKC_ARM_V8) || IS_ENABLED(CONFIG_HAKC_ARM_V9)

#undef hakc_noinline
#define hakc_noinline noinline

#define KERN_CLAQUE_BIT_MASK (0xFFFFFFFFFFF00000)
#define HAKC_CONTEXT_ADDR(ADDR) ((u64)(ADDR)&KERN_CLAQUE_BIT_MASK)
#define HAKC_COMPARTMENT_ADDR(ADDR) ((u64)(ADDR) & ~KERN_CLAQUE_BIT_MASK)
#define HAKC_UPPER_BIT_MASK (0xFF00000000000000)

#if IS_ENABLED(CONFIG_HAKC_LOG_FAILURE)
int hakc_create_proc_entry(void);
#endif

/* Smallest consecutive bytes that can be colored */
#define COLOR_GRANULARITY (1 << HAKC_COLOR_BIT_COUNT)

/* Round up to the nearest COLOR_GRANULARITY */
#define HAKC_ROUND_UP(x) (((((x)-1) | (COLOR_GRANULARITY - 1)) + 1))

#define HAKC_ADDRESS_BITS HAKC_VA_BITS

#define HAKC_KADDR(ADDR) (void *)(0xFFFF000000000000 | (u64)(ADDR))

typedef enum {
	SILVER_CLIQUE = 0xF0,
	GREEN_CLIQUE,
	RED_CLIQUE,
	ORANGE_CLIQUE,
	YELLOW_CLIQUE,
	PURPLE_CLIQUE,
	BLUE_CLIQUE,
	GREY_CLIQUE,
	PINK_CLIQUE,
	BROWN_CLIQUE,
	WHITE_CLIQUE,
	BLACK_CLIQUE,
	TEAL_CLIQUE,
	VIOLET_CLIQUE,
	CRIMSON_CLIQUE,
	GOLD_CLIQUE,
	START_CLIQUE = SILVER_CLIQUE,
	END_CLIQUE = START_CLIQUE + COLOR_GRANULARITY,
	INVALID_CLIQUE = END_CLIQUE
} clique_color_t;

#define HAKC_COLOR_COUNT (END_CLIQUE - START_CLIQUE)

typedef struct compartment_entry_token {
	hakc_compartment_id_t compartment;
	clique_access_tok_t entry_token;
} compartment_entry_tok_t;

extern bool hakc_initialized;// __read_mostly;
void hakc_init_tags(void);
void initialize_hakc(void);

#define VALID_COLOR(color) ((color) >= START_CLIQUE && (color) < END_CLIQUE)

#define HAKC_MASK_COLOR(COLOR) (1 << (COLOR - START_CLIQUE))

#define HAKC_CONTEXT(CLAQUE_ID, COLOR_MASK, TYPE)                               \
	(((TYPE)(CLAQUE_ID) << COLOR_GRANULARITY) | (COLOR_MASK))

#define PAC_MODIFIER(CLAQUE_ID, COLOR_MASK)                                    \
	HAKC_CONTEXT(CLAQUE_ID, COLOR_MASK, pac_salt_t)

#define HAKC_ENTRY_TOKEN(CLAQUE, ENTRY_COLORS)                                  \
	{                                                                      \
		.claque_id = CLAQUE, .entry_token = ENTRY_COLORS               \
	}
#define HAKC_EXIT(TARGET, ...)                                                  \
	static __attribute__((used))                                           \
		const claque_entry_tok_t __valid_targets[] = { TARGET,         \
							       ##__VA_ARGS__ }

uintptr_t hakc_pagetable_walk(const void *addr);

const char *get_hakc_color_name(clique_color_t color);

clique_color_t get_hakc_address_color(const void *addr);
clique_color_t get_hakc_percpu_color(const void * __percpu addr);

void hakc_color_address(const void *addr_to_color, clique_color_t color,
		       size_t size);

clique_color_t get_hakc_color_by_name(const char *color_name);

void *check_hakc_data_access(const void *address,
			     hakc_compartment_id_t compartment,
			    const clique_access_tok_t access_tok);
void* check_hakc_code_access(const void *address,
			     hakc_compartment_id_t compartment,
			    const clique_access_tok_t access_tok,
			    const compartment_entry_tok_t *valid_targets,
			    size_t n_targets);
void *get_code_address(const void* address, hakc_compartment_id_t compartment);

void *hakc_transfer_to_clique(void *data_to_transfer, size_t size,
			      hakc_compartment_id_t claque_id,
			      clique_color_t color,
			     bool is_code);

void *hakc_transfer_percpu(void __percpu *pcpu_ptr_base, size_t size,
			   hakc_compartment_id_t compartment,
			   clique_color_t color);

void *sign_data(const void *address, pac_salt_t modifier);
void *sign_code(const void *address, pac_salt_t modifier);
void *hakc_auth_data_ptr(const void *address, pac_salt_t modifier);
void *hakc_auth_code_ptr(const void *address, pac_salt_t modifier);
bool is_readonly(unsigned long addr);

void *hakc_sign_pointer(void *addr, hakc_compartment_id_t claque_id,
	clique_color_t color, bool is_code);

void __percpu * hakc_transfer_percpu_to_clique(void * __percpu original,
					      size_t size,
				     hakc_compartment_id_t claque_id,
				    clique_color_t color);
void __percpu *hakc_sign_pcpu_pointer_with_color(void __percpu *pcpu_ptr_base,
						 hakc_compartment_id_t
							 compartment);

void *hakc_sign_pointer_with_color(void *addr, hakc_compartment_id_t claque_id,
				  bool is_code);

static inline void *hakc_safe_ptr(unsigned long addr)
{
	if (!addr) {
		return (void *)addr;
	}
	return (void *)((unsigned long)HAKC_KADDR(addr) | HAKC_UPPER_BIT_MASK);
}

void *hakc_transfer_string(void *, hakc_compartment_id_t, clique_color_t);
struct sk_buff *hakc_transfer_skb(struct sk_buff *, hakc_compartment_id_t, clique_color_t);
const struct nlattr * const *hakc_transfer_nla(const struct nlattr * const [], size_t, hakc_compartment_id_t, clique_color_t);
struct file * hakc_transfer_file_struct(struct file *filep, hakc_compartment_id_t compartment, clique_color_t color);
struct socket* hakc_transfer_socket(struct socket *socket, hakc_compartment_id_t compartment, clique_color_t color);

#define HAKC_GET_SAFE_PTR(ptr) ((typeof(ptr))hakc_safe_ptr((unsigned long)(ptr)))

#define MODULE_CLAQUE(mod) (mod)->claque_id

#define HAKC_OUTSIDE_TRANSFER_FUNC(func) HAKC_XFER_##func

#define DEFINE_HAKC_OUTSIDE_TRANSFER_FUNC(func, rettype, args...)  \
	rettype HAKC_OUTSIDE_TRANSFER_FUNC(func)(args)

/*
 * typedef for module parameter Get HAKC Context (hakc_modparam_getctx)
 * function pointers
 * int64_t getctx(void *param_pointer, int64_t tok_or_col);
 * pass 0 as value of tok_or_col to get HAKC access token (context)
 * pass 1 as value of tok_or_col to get HAKC color
 */
typedef int64_t(*getctx_fp)(void *, int64_t);

static inline bool is_userspace_addr(const void *addr)
{
	/* Bits 48:63 are one for kernel addresses */
	return ((UL(1) << HAKC_VA_BITS) > (unsigned long)addr);
}

static inline bool addr_is_signed(const void *ptr)
{
	unsigned long p = (unsigned long)ptr;
	unsigned int upper_bits = (p >> HAKC_ADDRESS_BITS);
	return (upper_bits > 0 && upper_bits != 0xFFFF);
}

int hakc_duplicate_readonly_charp(const struct kernel_param *kp);
int hakc_transfer_charp(const struct kernel_param *kp);

#else /* ! IS_ENABLED(CONFIG_HAKC) */

#define HAKC_GET_SAFE_PTR(ptr) ptr

#define HAKC_SYMBOL_CLAQUE(SYM, CLAQUE_ID, COLOR, ...)

#define DEFINE_HAKC_OUTSIDE_TRANSFER_FUNC(func, rettype, args...) func
#define HAKC_OUTSIDE_TRANSFER_FUNC(func) func
#define hakc_sign_pointer_with_color(addr, claque_id, is_code)	addr

#endif /* IS_ENABLED(CONFIG_HAKC) */

#endif /* LINUX_HAKC_HAKC_H */
