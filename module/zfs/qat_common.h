/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

#ifndef _SYS_QAT_COMMON_H
#define _SYS_QAT_COMMON_H

#if defined(_KERNEL) && defined(HAVE_QAT)

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/completion.h>
#include <sys/zfs_context.h>

#include <cpa.h>

#define	PHYS_CONTIG_ALLOC(pp_mem_addr, size_bytes)	\
	mem_alloc_contig((void *)(pp_mem_addr), (size_bytes), 1)

#define PHYS_CONTIG_ALLOC_ALIGNED(ppMemAddr, sizeBytes, alignment)	\
	mem_alloc_contig((void *)(ppMemAddr), (sizeBytes), (alignment))

#define	PHYS_CONTIG_FREE(p_mem_addr)	\
	mem_free_contig((void *)&(p_mem_addr))

#define VIRT_ALLOC(pp_mem_addr, size_bytes)	\
	mem_alloc_virtual((void *)(pp_mem_addr), (size_bytes))

#define VIRT_FREE(p_mem_addr)	\
	mem_free_virtual((void *)&(p_mem_addr))

extern CpaStatus mem_alloc_contig(void **ppMemAddr, const Cpa32U sizeBytes, const Cpa32U alignment);
extern void mem_free_contig(void **ppMemAddr);

extern CpaStatus mem_alloc_virtual(void **ppMemAddr, const Cpa32U sizeBytes);
extern void mem_free_virtual(void **ppMemAddr);

#define ceil(n, d) (((n) < 0) ? (-((-(n))/(d))) : (n)/(d) + ((n)%(d) != 0))

extern int zfs_qat_init_failure_threshold;
extern int zfs_qat_disable;

#endif // kernel/qat

#endif // defined
