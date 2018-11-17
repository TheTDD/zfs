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
// #include <sys/zfs_context.h>

#include <cpa.h>

#define QAT_DEBUG 0

typedef struct qat_highmem
{
	struct page *page;
	uint8_t order;
	void *ptr;
} qat_highmem_t;

#define HIGHMEM_CONTIG_ALLOC(ptr, size) highmem_alloc(ptr, size)
#define HIGHMEM_CONTIG_FREE(ptr) highmem_free(&(ptr))

CpaStatus highmem_alloc(qat_highmem_t *addr, uint16_t size);
void highmem_free(qat_highmem_t* addr);

/*
* INTEL: For optimal performance, data pointers should be 8-byte aligned. In some cases this is a
* requirement, while in most other cases, it is a recommendation for performance.
*/

/*
For optimal performance, ensure the following:
• All data buffers should be aligned on a 64-byte boundary.
• Transfer sizes that are multiples of 64 bytes are optimal.
• Small data transfers (less than 64 bytes) should be avoided. If a small data
  transfer is needed, consider embedding this within a larger buffer so that the
  transfer size is a multiple of 64 bytes. Offsets can then be used to identify the
  region of interest within the larger buffer.
• Each buffer entry within a Scatter-Gather-List (SGL) should be a multiple of
  64bytes and should be aligned on a 64-byte boundary.
*/

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
#define multipleOf64(n) (64 * ceil((n), 64))

extern int zfs_qat_init_failure_threshold;
extern int zfs_qat_disable;

#define USEC_IN_SEC     1000000UL

#define DESTROY_CACHE(cache) if (NULL != cache) { kmem_cache_destroy(cache); cache = NULL; }

#define DEFAULT_ALIGN_CACHE 	8
#define DEFAULT_ALIGN_ALLOC	1

#endif // kernel/qat

#endif // defined
