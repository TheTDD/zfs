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
#include <linux/completion.h>
#include <sys/zfs_context.h>

#include <cpa.h>

#ifdef __x86_64__
#define ADDR_LEN uint64_t
#else
#define ADDR_LEN uint32_t
#endif

CpaStatus
mem_alloc_contig(void **ppMemAddr, const Cpa32U sizeBytes, const Cpa32U alignment)
{
    void *pAlloc = NULL;
    uint32_t align = 0;

    pAlloc = kmalloc_node((sizeBytes + alignment + sizeof(void *)), GFP_KERNEL, 0);
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

int zfs_qat_init_failure_threshold = 100;

module_param(zfs_qat_init_failure_threshold, int, 0644);
MODULE_PARM_DESC(zfs_qat_init_failure_threshold, "Threshold (number of init failures) to consider disabling QAT");

#endif
