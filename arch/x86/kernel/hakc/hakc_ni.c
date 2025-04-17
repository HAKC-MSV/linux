#include <linux/hakc/hakc.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <uapi/linux/netlink.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <crypto/hash.h>

//#define HAKC_DEBUG 1

#define HAKC_INFO(fmt, ...)                                                    \
        if (HAKC_DEBUG) {                                                      \
                pr_info(fmt, ##__VA_ARGS__);                                   \
        }
#define HAKC_ERR(fmt, ...)                                                     \
        if (HAKC_DEBUG) {                                                      \
                pr_err(fmt, ##__VA_ARGS__);                                    \
        }

struct percpu_info {
	void *signed_addr;
	bool is_percpu, is_dynamic;
	void *percpu_addr;
};

#if !IS_ENABLED(CONFIG_HAKC_X86_SIGN_SSSE3) && \
	!IS_ENABLED(CONFIG_HAKC_X86_SIGN_NI)
#error "Must select one of HAKC_X86_SIGN_SSSE3 " \
	"or HAKC_X86_SIGN_NI in kernel config"
#endif

const char* impl_str = "KERN";

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}


static int calc_hash(struct crypto_shash *alg,
             const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}
static const char *hash_alg_name = "sha256";

// this uses whatever the kernel thinks is the best implementation

static inline void *ni_sha256_hash_address_with_modifier(const void *address,
							pac_salt_t modifier)
{
	struct crypto_shash *__alg;
	unsigned char __digest[256];
	unsigned char __data[64];

	void *result;

	__alg = NULL;
	__alg = crypto_alloc_shash(hash_alg_name, 0, 0);
	if(IS_ERR(__alg)){
		pr_info("can't alloc alg %s\n", hash_alg_name);
		//return PTR_ERR(alg);
       	}
        if (!__alg) return (void*)0xaaaaaaaaaaaaaaaa;

	preempt_disable();
	memset(__digest, 0, 256);
	memset(__data, 0, 64);
	*((uint64_t *)&__data[0]) = (uint64_t)modifier;
	*((uint64_t *)&__data[8]) = (uint64_t)((uint64_t)address & 0xff00ffffffffffffL);
//	*((uint64_t *)&data[16]) = (uint64_t)modifier;
//	*((uint64_t *)&data[24]) = (uint64_t)((uint64_t)address & 0xff00ffffffffffffL);

        calc_hash(__alg, __data, 64, __digest);
	crypto_free_shash(__alg);
        uint64_t res = 0;
	memcpy(&res, &__digest[0], 8);
	preempt_enable();
//	uintptr_t tmp_addr = (uintptr_t)address;

//	printk("addr %llx mod %llx res %llx\n", (uint64_t)((uint64_t)address&0xff00ffffffffffffL), (uint64_t)modifier, (uint64_t)res);
//	printk("\taddr byte %llx , res byte %llx\n", tmp_addr & 0x00ff000000000000, res & 0x00ff000000000000);

	if((res & 0x00ff000000000000l) == 0x00ff000000000000l) {
		res = 0x00fe000000000000l;
	}
	result = (void*)(((uintptr_t)address & 0xff00ffffffffffffL) | (res & 0x00ff000000000000l));

	return result;
}

void *sign_data(const void *address, pac_salt_t modifier)
{
	void *result;
	HAKC_INFO("%s: Signing data pointer %p with salt %llx\n", impl_str,
		  address, modifier);

	result = ni_sha256_hash_address_with_modifier(address, modifier);

	return result;
}

void *sign_code(const void *address, pac_salt_t modifier)
{
	void *result;
	HAKC_INFO("%s: Signing code pointer %p with salt %llx\n", impl_str,
		  address, modifier);

	result = ni_sha256_hash_address_with_modifier(address, modifier);

	return result;
}

void *hakc_auth_data_ptr(const void *address, pac_salt_t modifier)
{
	void *result;
	void *hashed_result;
	HAKC_INFO("%s: Authenticating data at %p with salt %llx\n", impl_str,
		  address, modifier);

	hashed_result = ni_sha256_hash_address_with_modifier(address,
								modifier);

	if (hashed_result == address) {
		HAKC_INFO("hashed result matches\n");
		result = (void *)((uintptr_t)address | 0x00ff000000000000L);
	} else {
		result = (void*)hashed_result;
	}

	if (HAKC_DEBUG && 0) {
		pr_info("result: %p\n", result);
	}
	return result;
}

void *hakc_auth_code_ptr(const void *address, pac_salt_t modifier)
{
	void *result;
	void *hashed_result;
	HAKC_INFO("%s: Authenticating code at %p with salt %llx\n", impl_str,
		  address, modifier);

	hashed_result = ni_sha256_hash_address_with_modifier(address,
								modifier);

	if (hashed_result == address) {
		HAKC_INFO("hashed result matches\n");
		result = (void *)((uintptr_t)address | 0x00ff000000000000L);
	} else {
		result = (void*)hashed_result;
	}
	return result;
}

bool is_readonly(unsigned long addr)
{
	pte_t *pte;
	/* TODO: Figure out why pte_write sometimes returns true when the
	 * page is read-only */
	if (is_kernel_rodata(addr)) {
		return true;
	} else if (is_kernel_text(addr)) {
		return true;
	}
	pte = virt_to_kpte(addr);
	return pte_present(*pte) && !pte_write(*pte);
}
