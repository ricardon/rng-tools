/*
 * rngd_source.h -- Entropy source and conditioning
 *
 * Copyright (C) 2001 Philipp Rumpf
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef RNGD_ENTSOURCE__H
#define RNGD_ENTSOURCE__H

#include "rng-tools-config.h"

#include <unistd.h>
#include <stdint.h>

/* Struct for CPUID return values */
struct cpuid {
        uint32_t eax, ecx, edx, ebx;
};

/* Logic and contexts */
extern fips_ctx_t fipsctx;		/* Context for the FIPS tests */
extern fips_ctx_t tpm_fipsctx;	/* Context for the tpm FIPS tests */

/* Inline assembly to check eflags */
/* Only necessary on 32 bit processor */
#if defined (__i386__)
int x86_has_eflag(uint32_t flag);
#endif

/* Inline assembly for CPUID call for RDRAND */
extern int x86_rdrand_nlong(void *ptr, size_t count);	/* RDRAND-access logic */
extern void x86_aes_mangle(void *data, void *state);	/* Conditioning RDRAND for seed-grade entropy */

/*
 * Initialize entropy source and entropy conditioning
 *
 * sourcedev is the path to the entropy source
 */
extern int init_entropy_source(struct rng *);
extern int init_drng_entropy_source(struct rng *);
extern int init_tpm_entropy_source(struct rng *);

/* Read data from the entropy source */
extern int xread(void *buf, size_t size, struct rng *ent_src);
extern int xread_drng(void *buf, size_t size, struct rng *ent_src);
extern int xread_tpm(void *buf, size_t size, struct rng *ent_src);

#endif /* RNGD_ENTSOURCE__H */
