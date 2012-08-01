/*
 * Copyright (c) 2011, Intel Corporation
 * Authors: Fenghua Yu <fenghua.yu@intel.com>,
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

#define ENTRY(x)	  \
	.balign	64	; \
	.globl	x	; \
x:

#define ENDPROC(x)		  \
	.size	x, .-x		; \
	.type	x, @function

#define RDRAND_RETRY_LIMIT	10

#if defined(__x86_64__)

ENTRY(x86_rdrand_nlong)
1:
	mov	$RDRAND_RETRY_LIMIT, %eax
2:
	.byte	0x48,0x0f,0xc7,0xf2	/* rdrand %rdx */
	jnc	3f
	mov	%rdx, (%rdi)
	add	$8, %rdi
	sub	$1, %esi
	jnz	1b
	ret
3:
	sub	$1, %eax
	rep;nop
	jnz	2b
	ret
ENDPROC(x86_rdrand_nlong)

#define SETPTR(var,ptr)	leaq var(%rip),ptr
#define PTR0	%rdi
#define PTR1	%rsi
#define PTR2	%rcx
#define NPTR2	1	/* %rcx = %r1, only 0-7 valid here */

#elif defined(__i386__)

ENTRY(x86_rdrand_nlong)
	push	%ebp
	mov	%esp, %ebp
	push	%edi
	movl	8(%ebp), %ecx
	movl	12(%ebp), %edx
1:
	mov	$RDRAND_RETRY_LIMIT, %eax
2:
	.byte	0x0f,0xc7,0xf7		/* rdrand %edi */
	jnc	3f
	mov	%edi, (%ecx)
	add	$4, %ecx
	sub	$1, %edx
	jnz	2b
	pop	%edi
	pop	%ebp
	ret
3:
	sub	$1, %eax
	rep;nop
	jnz	2b
	pop %edi
	pop	%ebp
	ret
ENDPROC(x86_rdrand_nlong)

#define SETPTR(var,ptr)	movl $(var),ptr
#define PTR0	%eax
#define PTR1	%edx
#define PTR2	%ecx
#define NPTR2	1	/* %rcx = %r1 */

#endif

#if defined(__i386__) || defined(__x86_64__)

ENTRY(x86_aes_mangle)
#if defined(__i386__)
	push	%ebp
	mov	%esp, %ebp
	movl	8(%ebp), %eax
	movl	12(%ebp), %edx
#endif

	SETPTR(aes_round_keys, PTR2)

	movdqa	(0*16)(PTR0), %xmm0
	movdqa	(1*16)(PTR0), %xmm1
	movdqa	(2*16)(PTR0), %xmm2
	movdqa	(3*16)(PTR0), %xmm3
	movdqa	(4*16)(PTR0), %xmm4
	movdqa	(5*16)(PTR0), %xmm5
	movdqa	(6*16)(PTR0), %xmm6
	movdqa	(7*16)(PTR0), %xmm7

	pxor	(0*16)(PTR1), %xmm0
	pxor	(1*16)(PTR1), %xmm1
	pxor	(2*16)(PTR1), %xmm2
	pxor	(3*16)(PTR1), %xmm3
	pxor	(4*16)(PTR1), %xmm4
	pxor	(5*16)(PTR1), %xmm5
	pxor	(6*16)(PTR1), %xmm6
	pxor	(7*16)(PTR1), %xmm7

	.rept 10
	.byte	0x66,0x0f,0x38,0xdc,0x00+NPTR2	/* aesenc (PTR2), %xmm0 */
	.byte	0x66,0x0f,0x38,0xdc,0x08+NPTR2	/* aesenc (PTR2), %xmm1 */
	.byte	0x66,0x0f,0x38,0xdc,0x10+NPTR2	/* aesenc (PTR2), %xmm2 */
	.byte	0x66,0x0f,0x38,0xdc,0x18+NPTR2	/* aesenc (PTR2), %xmm3 */
	.byte	0x66,0x0f,0x38,0xdc,0x20+NPTR2	/* aesenc (PTR2), %xmm4 */
	.byte	0x66,0x0f,0x38,0xdc,0x28+NPTR2	/* aesenc (PTR2), %xmm5 */
	.byte	0x66,0x0f,0x38,0xdc,0x30+NPTR2	/* aesenc (PTR2), %xmm6 */
	.byte	0x66,0x0f,0x38,0xdc,0x38+NPTR2	/* aesenc (PTR2), %xmm7 */
	add	$16, PTR2
	.endr

	.byte	0x66,0x0f,0x38,0xdd,0x00+NPTR2	/* aesenclast (PTR2), %xmm0 */
	.byte	0x66,0x0f,0x38,0xdd,0x08+NPTR2	/* aesenclast (PTR2), %xmm1 */
	.byte	0x66,0x0f,0x38,0xdd,0x10+NPTR2	/* aesenclast (PTR2), %xmm2 */
	.byte	0x66,0x0f,0x38,0xdd,0x18+NPTR2	/* aesenclast (PTR2), %xmm3 */
	.byte	0x66,0x0f,0x38,0xdd,0x20+NPTR2	/* aesenclast (PTR2), %xmm4 */
	.byte	0x66,0x0f,0x38,0xdd,0x28+NPTR2	/* aesenclast (PTR2), %xmm5 */
	.byte	0x66,0x0f,0x38,0xdd,0x30+NPTR2	/* aesenclast (PTR2), %xmm6 */
	.byte	0x66,0x0f,0x38,0xdd,0x38+NPTR2	/* aesenclast (PTR2), %xmm7 */

	movdqa	%xmm0, (0*16)(PTR0)
	movdqa	%xmm1, (1*16)(PTR0)
	movdqa	%xmm2, (2*16)(PTR0)
	movdqa	%xmm3, (3*16)(PTR0)
	movdqa	%xmm4, (4*16)(PTR0)
	movdqa	%xmm5, (5*16)(PTR0)
	movdqa	%xmm6, (6*16)(PTR0)
	movdqa	%xmm7, (7*16)(PTR0)

	movdqa	%xmm0, (0*16)(PTR1)
	movdqa	%xmm1, (1*16)(PTR1)
	movdqa	%xmm2, (2*16)(PTR1)
	movdqa	%xmm3, (3*16)(PTR1)
	movdqa	%xmm4, (4*16)(PTR1)
	movdqa	%xmm5, (5*16)(PTR1)
	movdqa	%xmm6, (6*16)(PTR1)
	movdqa	%xmm7, (7*16)(PTR1)

#if defined(__i386__)
	pop	%ebp
#endif
	ret
ENDPROC(x86_aes_mangle)
	/*
	 * AES round keys for an arbitrary key:
	 * 00102030405060708090A0B0C0D0E0F0
	 */
	.section ".rodata","a"
	.balign	16
aes_round_keys:
	.long	0x00102030, 0x40506070, 0x8090A0B0, 0xC0D0E0F0
	.long	0x89D810E8, 0x855ACE68, 0x2D1843D8, 0xCB128FE4
	.long	0x4915598F, 0x55E5D7A0, 0xDACA94FA, 0x1F0A63F7
	.long	0xFA636A28, 0x25B339C9, 0x40668A31, 0x57244D17
	.long	0x24724023, 0x6966B3FA, 0x6ED27532, 0x88425B6C
	.long	0xC81677BC, 0x9B7AC93B, 0x25027992, 0xB0261996
	.long	0xC62FE109, 0xF75EEDC3, 0xCC79395D, 0x84F9CF5D
	.long	0xD1876C0F, 0x79C4300A, 0xB45594AD, 0xD66FF41F
	.long	0xFDE3BAD2, 0x05E5D0D7, 0x3547964E, 0xF1FE37F1
	.long	0xBD6E7C3D, 0xF2B5779E, 0x0B61216E, 0x8B10B689
	.long	0x69C4E0D8, 0x6A7B0430, 0xD8CDB780, 0x70B4C55A
	.size	aes_round_keys, .-aes_round_keys

	.bss
	.balign 16
aes_fwd_state:
	.space	16
	.size	aes_fwd_state, .-aes_fwd_state

#endif /* i386 or x86_64 */

/*
 * This is necessary to keep the whole executable
 * from needing a writable stack.
 */
                .section        .note.GNU-stack,"",%progbits
