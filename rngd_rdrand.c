/*
 * Copyright (c) 2012, Intel Corporation
 * Authors: Richard B. Hill <richard.b.hill@intel.com>,
 *          H. Peter Anvin <hpa@linux.intel.com>
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

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"

#if defined(__i386__) || defined(__x86_64__)

/* Initialization vector and msg sizes for standard AES usage */
#define IV_SIZE			(16*1)
#define MSG_SIZE		(16*7)
#define CHUNK_SIZE		(16*8)

/* Struct for CPUID return values */
struct cpuid {
        uint32_t eax, ecx, edx, ebx;
};

/* Get data from RDRAND */
extern int x86_rdrand_nlong(void *ptr, size_t count);
/* Conditioning RDRAND for seed-grade entropy */
extern void x86_aes_mangle(void *data, void *state);

/* Checking eflags to confirm cpuid instruction available */
/* Only necessary for 32 bit processors */
#if defined (__i386__)
static int x86_has_eflag(uint32_t flag)
{
        uint32_t f0, f1;
		asm("pushfl ; "
            "pushfl ; "
            "popl %0 ; "
            "movl %0,%1 ; "
            "xorl %2,%1 ; "
            "pushl %1 ; "
            "popfl ; "
            "pushfl ; "
            "popl %1 ; "
            "popfl"
            : "=&r" (f0), "=&r" (f1)
            : "ri" (flag));
        return !!((f0^f1) & flag);
}
#endif

/* Calling cpuid instruction to verify rdrand capability */
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

/* Read data from the drng
 * in chunks of 128 bytes for AES scrambling */
int xread_drng(void *buf, size_t size, struct rng *ent_src)
{
	size_t psize = size;
	size_t off = 0;
	ssize_t r = 0;
	int rdrand_round_count = size / 128;

	static unsigned char iv_buf[IV_SIZE] __attribute__((aligned(128)));
	static unsigned char m_buf[MSG_SIZE] __attribute__((aligned(128)));
	static unsigned char tmp[CHUNK_SIZE] __attribute__((aligned(128)));
	static unsigned char fwd[CHUNK_SIZE] __attribute__((aligned(128)));
	int i;

	while (size > 0 && size <= psize) {
		for (i = 0; i < rdrand_round_count && size <= psize; i++) {
			if (!x86_rdrand_nlong(iv_buf, sizeof(iv_buf)/sizeof(long))) {
				r = -1;
				break;
			}
			if (!x86_rdrand_nlong(m_buf, sizeof(m_buf)/sizeof(long))) {
				r = -1;
				break;
			}
			memcpy(tmp, iv_buf, IV_SIZE);
			memcpy(tmp+IV_SIZE, m_buf, MSG_SIZE);

			x86_aes_mangle(tmp, fwd);
			r = (sizeof(tmp) > size)? size : sizeof(tmp);

			if (r <= 0)
				break;
			memcpy(buf+off, tmp, r);
			off += r;
			size -= r;
		}
		if (r <= 0)
			break;
	}

	if (size > 0 && size < psize) {
		message(LOG_DAEMON|LOG_ERR, "read error\n");
		return -1;
	}
	return 0;
}

/*
 * Confirm RDRAND capabilities for drng entropy source
 */
int init_drng_entropy_source(struct rng *ent_src)
{
	struct cpuid info;
	/* We need RDRAND and AESni */
	const uint32_t need_features_ecx1 = (1 << 30) | (1 << 25);

#if defined(__i386__)
	if (!x86_has_eflag(1 << 21))
		return 1;	/* No CPUID instruction */
#endif

	cpuid(0, 0, &info);
	if (info.eax < 1)
		return 1;
	cpuid(1, 0, &info);
	if ((info.ecx & need_features_ecx1) != need_features_ecx1)
		return 1;

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
