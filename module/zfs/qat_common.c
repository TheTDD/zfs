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

#if defined(_KERNEL) && defined(HAVE_QAT)

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <sys/zfs_context.h>

#include <cpa.h>

#include "qat_common.h"

#ifdef __x86_64__
#define ADDR_LEN uint64_t
#else
#define ADDR_LEN uint32_t
#endif

static inline CpaStatus
_mem_alloc_contig(void **ppMemAddr, const Cpa32U sizeBytes)
{
    void *pAlloc = NULL;

    /* set to NULL even if it fails to avoid problems with deallocation */
    *ppMemAddr = NULL;

    pAlloc = kmalloc((sizeBytes + sizeof(void *)), GFP_KERNEL);
    if (NULL == pAlloc)
    {
	return CPA_STATUS_RESOURCE;
    }

    *ppMemAddr = pAlloc + sizeof(void *);
    *(ADDR_LEN *)(*ppMemAddr - sizeof(void *)) = (ADDR_LEN)pAlloc;

    return CPA_STATUS_SUCCESS;

}

static inline CpaStatus
_mem_alloc_contig_aligned(void **ppMemAddr, const Cpa32U sizeBytes, const Cpa32U alignment)
{
    void *pAlloc = NULL;
    uint32_t align = 0;

    /* set to NULL even if it fails to avoid problems with deallocation */
    *ppMemAddr = NULL;

    // pAlloc = kmalloc_node((sizeBytes + alignment + sizeof(void *)), GFP_KERNEL, 0);
    pAlloc = kmalloc((sizeBytes + alignment + sizeof(void *)), GFP_KERNEL);
    if (NULL == pAlloc)
    {
	return CPA_STATUS_RESOURCE;
    }

    *ppMemAddr = pAlloc + sizeof(void *);
    align = ((ADDR_LEN)(*ppMemAddr)) % alignment;

    *ppMemAddr += (alignment - align);
    *(ADDR_LEN *)(*ppMemAddr - sizeof(void *)) = (ADDR_LEN)pAlloc;

    return CPA_STATUS_SUCCESS;
}

CpaStatus
mem_alloc_contig(void **ppMemAddr, const Cpa32U sizeBytes, const Cpa32U alignment)
{
	CpaStatus status = CPA_STATUS_FAIL;
	switch (alignment)
	{
		case 0:
		case 1:
			status = _mem_alloc_contig(ppMemAddr, sizeBytes);
			break;
		default:
			status = _mem_alloc_contig_aligned(ppMemAddr, sizeBytes, alignment);
			break;
	}

	return status;
}

void
mem_free_contig(void **ppMemAddr)
{
    void *pAlloc = NULL;
    if (NULL != *ppMemAddr)
    {
        pAlloc = (void *)(*((ADDR_LEN *)(*ppMemAddr - sizeof(void *))));
        kfree(pAlloc);
        *ppMemAddr = NULL;
    }
}

CpaStatus
mem_alloc_virtual(void **ppMemAddr, const Cpa32U sizeBytes) 
{
    *ppMemAddr = vmalloc(sizeBytes);

    if (NULL == *ppMemAddr) 
    {
	return CPA_STATUS_RESOURCE;
    }

    return CPA_STATUS_SUCCESS;
}

void
mem_free_virtual(void **ppMemAddr) 
{
    if (NULL != *ppMemAddr) 
    {
	vfree(*ppMemAddr);
	*ppMemAddr = NULL;
    }
}

static inline int
find_order(uint16_t bytes)
{

        int i;
        int result = -1;

        for (i=0; i<MAX_ORDER; i++)
        {

                if (bytes <= PAGE_SIZE * (1 << i))
                {
                        result = i;
                        break;
                }
        }

        return result;

}

CpaStatus highmem_alloc(qat_highmem_t *addr, uint16_t size)
{
	CpaStatus status = CPA_STATUS_FAIL;
	struct page *page = NULL;
	void *memory = NULL;
	int order = find_order(size);

	// clean structure to avoid issues by deallocations
	memset(addr, 0 , sizeof(qat_highmem_t));

	if (order >= 0)
	{
		page = alloc_pages(GFP_HIGHUSER, order);
		if (page == NULL)
		{
		    printk(KERN_ALERT "page allocation for %ld bytes failed\n", (long)PAGE_SIZE * (1 << order));
		    status = CPA_STATUS_RESOURCE;
		    goto out;
		}

		// TODO: kmap_nonblock doesn't exist
		memory = kmap(page);
		if (memory == NULL)
		{
		    __free_pages(page, order);
		    printk(KERN_ALERT "page mapping for %ld bytes failed\n", (long)PAGE_SIZE * (1 << order));
		    status = CPA_STATUS_RESOURCE;
		    goto out;
		}

		addr->page = page;
		addr->ptr = memory;
		addr->order = order;
		status = CPA_STATUS_SUCCESS;
	}

out:

	return status;

}

void highmem_free(qat_highmem_t* addr)
{
	if (addr->ptr != NULL && addr->page != NULL)
	{
		kunmap(addr->page);
	}

	if (addr->page != NULL)
	{
		__free_pages(addr->page, addr->order);
	}

	memset(addr, 0, sizeof(qat_highmem_t));
}

int zfs_qat_init_failure_threshold = 100;
int zfs_qat_disable = 0;

module_param(zfs_qat_init_failure_threshold, int, 0644);
MODULE_PARM_DESC(zfs_qat_init_failure_threshold, "Threshold (number of init failures) to consider disabling QAT");

module_param(zfs_qat_disable, int, 0644);
MODULE_PARM_DESC(zfs_qat_disable, "completely disable any access to QAT");

#endif
