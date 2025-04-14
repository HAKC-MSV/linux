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

/*
 * See FIPS 180-4, Section 5.3.3:
 * "SHA-256
 * For SHA-256, the initial hash value, H(0), shall consist of the following
 * eight 32-bit words, in hex:
 * ...
 * These words were obtained by taking the first thirty-two bits of
 * the fractional parts of the square roots of the first eight prime numbers."
 */
const uint32_t H_0[8] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
};

#if !IS_ENABLED(CONFIG_HAKC_X86_SIGN_SSSE3) && \
	!IS_ENABLED(CONFIG_HAKC_X86_SIGN_NI)
#error "Must select one of HAKC_X86_SIGN_SSSE3 " \
	"or HAKC_X86_SIGN_NI in kernel config"
#endif

#if IS_ENABLED(CONFIG_HAKC_X86_SIGN_SSSE3)
void sha256_transform_ssse3(u32 *digest, const void *data, unsigned int num_blks);
const char* impl_str = "SSSE3";
#endif

#if IS_ENABLED(CONFIG_HAKC_X86_SIGN_NI)
void sha256_ni_transform(u32 *digest, const void *data, unsigned int num_blks);
const char* impl_str = "NI";
#endif

static inline void *ni_sha256_hash_address_with_modifier(const void *address,
							pac_salt_t modifier)
{
	uint32_t H[8];
	unsigned char buffer[64];
	uint64_t h0;
	void *result;

	memcpy(H, H_0, 8*4);
	memset(buffer, 0, 64);

	*((pac_salt_t *)&buffer[0]) = modifier;
	*((uintptr_t *)&buffer[sizeof(pac_salt_t *)]) =
		(uintptr_t)((uintptr_t)address & 0xff00ffffffffffffL);

	/*
	 * I don't know if this state is saved/restored correctly
	 * on context switch
	 * match the behavior of ARM v8 HAKC
	 */
	preempt_disable();
#if IS_ENABLED(CONFIG_HAKC_X86_SIGN_NI)
	sha256_ni_transform(H, buffer, 1);
#endif
#if IS_ENABLED(CONFIG_HAKC_X86_SIGN_SSSE3)
	sha256_transform_ssse3(H, buffer, 1);
#endif
	preempt_enable();

	h0 = (uint64_t)H[0];

	if ((h0 & 0xff000000) == 0xff000000) {
		h0 = (uint64_t)0xfe000000 << 24;
	} else {
		h0 = (h0 & 0xff000000) << 24;
	}
	result = (void*)(((uintptr_t)address & 0xff00ffffffffffffL) | h0);

	return result;
}

static inline void *sign_data(const void *address, pac_salt_t modifier)
{
	void *result;
	HAKC_INFO("%s: Signing data pointer %p with salt %llx\n", impl_str,
		  address, modifier);

	result = ni_sha256_hash_address_with_modifier(address, modifier);

	return result;
}

static inline void *sign_code(const void *address, pac_salt_t modifier)
{
	void *result;
	HAKC_INFO("%s: Signing code pointer %p with salt %llx\n", impl_str,
		  address, modifier);

	result = ni_sha256_hash_address_with_modifier(address, modifier);

	return result;
}

static inline void *hakc_auth_data_ptr(const void *address, pac_salt_t modifier)
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

static inline void *hakc_auth_code_ptr(const void *address, pac_salt_t modifier)
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

static inline bool is_readonly(unsigned long addr)
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
