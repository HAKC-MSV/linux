#include <linux/hakc/hakc.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <uapi/linux/netlink.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/neon.h>

#define SIGNING_DEBUG 0

void sha256_block_neon(u32 *digest, const void *data, unsigned int num_blks);

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

static inline void *neon_sha256_hash_address_with_modifier(const void *address,
							pac_salt_t modifier)
{
	uint32_t H[8];
	unsigned char buffer[64];
	uint64_t h0;
	void *result;

	memcpy(H, H_0, 8*4);
	memset(buffer, 0, 64);

	*((pac_salt_t *)&buffer[0]) = modifier;
	*((uintptr_t *)&buffer[sizeof(pac_salt_t)]) =
		(uintptr_t)((uintptr_t)address & 0xff00ffffffffffffL);

#if SIGNING_DEBUG
	HAKC_INFO("buffer: %lx %lx %lx %lx %lx %lx %lx %lx\n",
		((uint64_t*)buffer)[0], ((uint64_t*)buffer)[1],
		((uint64_t*)buffer)[2],	((uint64_t*)buffer)[3],
		((uint64_t*)buffer)[4],	((uint64_t*)buffer)[5],
		((uint64_t*)buffer)[6],	((uint64_t*)buffer)[7]);
#endif
	/*
	 * NEON state not saved/not properly saved on context switch
	 * multi-threading issues have been encountered in practice
	 * with v5.10.24 kernel
	 */
	preempt_disable();
	sha256_block_neon(H, buffer, 1);
	preempt_enable();

	h0 = (uint64_t)H[0];
#if SIGNING_DEBUG
	HAKC_INFO("h0: %lx\n", h0);
#endif
	/*
	 * if chosen byte from hash ends up being ff
	 * the signed pointer will start with ffff
	 * indistinguishable from an unsigned kernel pointer
	 * instead of another round of hashing, use fe instead
	 */
	if ((h0 & 0xff000000) == 0xff000000) {
		h0 = (uint64_t)0xfe000000 << 24;
	} else {
		h0 = (h0 & 0xff000000) << 24;
	}
#if SIGNING_DEBUG
	HAKC_INFO("h0: %lx\n", h0);
#endif
	/* put the byte from the hash into the pointer */
	result = (void*)(((uintptr_t)address & 0xff00ffffffffffffL) | h0);
#if SIGNING_DEBUG
	HAKC_INFO("neon hash %lx %lx %lx\n", address, modifier, result);
#endif
	return result;
}

void *sign_data(const void *address, pac_salt_t modifier)
{
	void *result;
	HAKC_INFO("neon: Signing data pointer %lx with salt %lx\n", address,
		  modifier);

	result = neon_sha256_hash_address_with_modifier(address, modifier);

	return result;
}

void *sign_code(const void *address, pac_salt_t modifier)
{
	void *result;
	HAKC_INFO("neon: Signing code pointer %lx with salt %lx\n", address,
		  modifier);

	result = neon_sha256_hash_address_with_modifier(address, modifier);

	return result;
}

void *hakc_auth_data_ptr(const void *address, pac_salt_t modifier)
{
	void *result;
	void *hashed_result;
	HAKC_INFO("neon: Authenticating data at %lx with salt %lx\n", address,
		  modifier);

	hashed_result = neon_sha256_hash_address_with_modifier(address,
								modifier);

	if (hashed_result == address) {
		result = (void *)((uintptr_t)address | 0x00ff000000000000L);
	} else {
		result = (void*)hashed_result;
	}

	if (HAKC_DEBUG && 0) {
		pr_info("result: %lx\n", result);
	}
	return result;
}

void *hakc_auth_code_ptr(const void *address, pac_salt_t modifier)
{
	void *result;
	void *hashed_result;
	HAKC_INFO("neon: Authenticating code at %lx with salt %lx\n", address,
		  modifier);

	hashed_result = neon_sha256_hash_address_with_modifier(address,
								modifier);

	if (hashed_result == address) {
		result = (void *)((uintptr_t)address | 0x00ff000000000000L);
	} else {
		result = (void*)hashed_result;
	}
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
