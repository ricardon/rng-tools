/*
 * Copyright (c) 2012-2014, Intel Corporation
 * Authors: Richard B. Hill <richard.b.hill@intel.com>,
 *          H. Peter Anvin <hpa@linux.intel.com>,
 *          John P. Mechalas <john.p.mechalas@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#define _GNU_SOURCE

#ifndef HAVE_CONFIG_H
#error Invalid or missing autoconf build environment
#endif

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stddef.h>
#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"

#if defined(__i386__) || defined(__x86_64__)

/* Struct for CPUID return values */
struct cpuid {
        uint32_t eax, ecx, edx, ebx;
};

/*
 * Get data from RDRAND.  The count is in bytes, but the function can
 * round *up* the count to the nearest 4- or 8-byte boundary.  The caller
 * needs to take that into account.
 *
 * The function returns the number of bytes actually written.
 */
extern unsigned int x86_rdrand_bytes(void *ptr, unsigned int count);

/* Condition RDRAND for seed-grade entropy */
extern void x86_aes_mangle(void *data, void *state);

/* Expand an AES key for future use */
extern void x86_aes_expand_key(const void *key);

#ifdef __x86_64__
typedef uint64_t unative_t;	/* x86-64 or x32 */
#else
typedef uint32_t unative_t;	/* i386 */
#endif

/* Checking eflags to confirm cpuid instruction available */
static inline int x86_has_eflag(unative_t flag)
{
	unative_t f0, f1;
	asm("pushf ; "
	    "pushf ; "
	    "pop %0 ; "
	    "mov %0,%1 ; "
	    "xor %2,%1 ; "
	    "push %1 ; "
	    "popf ; "
	    "pushf ; "
	    "pop %1 ; "
	    "popf"
	    : "=&r" (f0), "=&r" (f1)
	    : "ri" (flag));
	return !!((f0^f1) & flag);
}

static inline int x86_has_cpuid(void)
{
#ifdef __i386__
	return x86_has_eflag(1 << 21); /* ID flag */
#else
	return 1;		/* x86-64 always has CPUID */
#endif
}

/* Calling cpuid instruction to verify rdrand and aes-ni capability */
static void cpuid(unsigned int leaf, unsigned int subleaf, struct cpuid *out)
{
#ifdef __i386__
    /* %ebx is a forbidden register if we compile with -fPIC or -fPIE */
    asm volatile("movl %%ebx,%0 ; cpuid ; xchgl %%ebx,%0"
                 : "=r" (out->ebx),
                   "=a" (out->eax),
                   "=c" (out->ecx),
                   "=d" (out->edx)
                 : "a" (leaf), "c" (subleaf));
#else
    asm volatile("cpuid"
                 : "=b" (out->ebx),
                   "=a" (out->eax),
                   "=c" (out->ecx),
                   "=d" (out->edx)
                 : "a" (leaf), "c" (subleaf));
#endif
}

/* Read data from the drng in chunks of 128 bytes for AES scrambling */
#define AES_BLOCK		16
#define CHUNK_SIZE		(AES_BLOCK*8)	/* 8 parallel streams */
#define RDRAND_ROUNDS		512		/* 512:1 data reduction */

static unsigned char iv_buf[CHUNK_SIZE] __attribute__((aligned(128)));
static int have_aesni;

/* Necessary if we have RDRAND but not AES-NI */

#ifdef HAVE_LIBGCRYPT

#define MIN_GCRYPT_VERSION "1.0.0"

static gcry_cipher_hd_t gcry_cipher_hd;

#endif

static inline int gcrypt_mangle(unsigned char *tmp)
{
#ifdef HAVE_LIBGCRYPT
	gcry_error_t gcry_error;

	/* Encrypt tmp in-place. */

	gcry_error = gcry_cipher_encrypt(gcry_cipher_hd, tmp,
					 AES_BLOCK * RDRAND_ROUNDS,
					 NULL, 0);

	if (gcry_error) {
		message(LOG_DAEMON|LOG_ERR,
			"gcry_cipher_encrypt error: %s\n",
			gcry_strerror(gcry_error));
		return -1;
	}
	return 0;
#else
	(void)tmp;
	return -1;
#endif
}

int xread_drng(void *buf, size_t size, struct rng *ent_src)
{
	char *p = buf;
	size_t chunk;
	void *data;
	unsigned char rdrand_buf[CHUNK_SIZE * RDRAND_ROUNDS]
		__attribute__((aligned(128)));
	unsigned int rand_bytes;
	int i;

	(void)ent_src;

	rand_bytes = have_aesni
		? CHUNK_SIZE * RDRAND_ROUNDS
		: AES_BLOCK * RDRAND_ROUNDS;

	while (size) {
		if (x86_rdrand_bytes(rdrand_buf, rand_bytes) != rand_bytes) {
			message(LOG_DAEMON|LOG_ERR, "read error\n");
			return -1;
		}

		/*
		 * Use 128-bit AES in CBC mode to reduce the
		 * data by a factor of RDRAND_ROUNDS
		 */
		if (have_aesni) {
			x86_aes_mangle(rdrand_buf, iv_buf);
			data = iv_buf;
			chunk = CHUNK_SIZE;
		} else if (!gcrypt_mangle(rdrand_buf)) {
			data = rdrand_buf + AES_BLOCK * (RDRAND_ROUNDS - 1);
			chunk = AES_BLOCK;
		} else {
			return -1;
		}

		chunk = (chunk > size) ? size : chunk;
		memcpy(p, data, chunk);
		p += chunk;
		size -= chunk;
	}

	return 0;
}

static int init_aesni(const void *key)
{
	if (!have_aesni)
		return 1;

	x86_aes_expand_key(key);
	return 0;
}

static int init_gcrypt(const void *key)
{
#ifdef HAVE_LIBGCRYPT
	gcry_error_t gcry_error;

	if (!gcry_check_version(MIN_GCRYPT_VERSION)) {
		message(LOG_DAEMON|LOG_ERR,
			"libgcrypt version mismatch: have %s, require >= %s\n",
			gcry_check_version(NULL), MIN_GCRYPT_VERSION);
		return 1;
	}

	gcry_error = gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER_AES128,
				      GCRY_CIPHER_MODE_CBC, 0);

	if (!gcry_error)
		gcry_error = gcry_cipher_setkey(gcry_cipher_hd, key, AES_BLOCK);

	if (!gcry_error) {
		/*
		 * Only need the first 16 bytes of iv_buf. AES-NI can
		 * encrypt multiple blocks in parallel but we can't.
		 */
		gcry_error = gcry_cipher_setiv(gcry_cipher_hd, iv_buf, AES_BLOCK);
	}

	if (gcry_error) {
		message(LOG_DAEMON|LOG_ERR,
			"could not set key or IV: %s\n",
			gcry_strerror(gcry_error));
		gcry_cipher_close(gcry_cipher_hd);
		return 1;
	}
	return 0;
#else
	(void)key;
	return 1;
#endif
}

/*
 * Confirm RDRAND capabilities for drng entropy source
 */
int init_drng_entropy_source(struct rng *ent_src)
{
	struct cpuid info;
	/* We need RDRAND, but AESni is optional */
	const uint32_t features_ecx1_rdrand = 1 << 30;
	const uint32_t features_ecx1_aesni  = 1 << 25;
	static unsigned char key[AES_BLOCK] = {
		0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,
		0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0
	}; /* AES data reduction key */
	unsigned char xkey[AES_BLOCK];	/* Material to XOR into the key */
	int fd;
	int i;

	if (!x86_has_cpuid())
		return 1;	/* No CPUID instruction */

	cpuid(0, 0, &info);
	if (info.eax < 1)
		return 1;
	cpuid(1, 0, &info);
	if (!(info.ecx & features_ecx1_rdrand))
		return 1;

	have_aesni = !!(info.ecx & features_ecx1_aesni);

	/* Randomize the AES data reduction key the best we can */
	if (x86_rdrand_bytes(xkey, sizeof xkey) != sizeof xkey)
		return 1;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		read(fd, key, sizeof key);
		close(fd);
	}

	for (i = 0; i < sizeof key; i++)
		key[i] ^= xkey[i];

	/* Initialize the IV buffer */
	if (x86_rdrand_bytes(iv_buf, CHUNK_SIZE) != CHUNK_SIZE)
		return 1;

	if (init_aesni(key) && init_gcrypt(key))
		return 1;	/* We need one crypto or the other... */

	src_list_add(ent_src);
	/* Bootstrap FIPS tests */
	ent_src->fipsctx = malloc(sizeof(fips_ctx_t));
	fips_init(ent_src->fipsctx, 0);
	return 0;
}

#else /* Not i386 or x86-64 */

int init_drng_entropy_source(struct rng *ent_src)
{
	(void)ent_src;
	return 1;
}

int xread_drng(void *buf, size_t size, struct rng *ent_src)
{
	(void)buf;
	(void)size;
	(void)ent_src;

	return -1;
}

#endif /* Not i386 or x86-64 */
