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
#include <linux/rwlock.h>
#include <sys/zfs_context.h>

#include <cpa.h>
#include <lac/cpa_cy_im.h>
#include <lac/cpa_cy_sym_dp.h>
#include <icp_sal_poll.h>

#include "qat_common.h"
#include "qat_cy_common.h"

/*
 * Within the scope of this file file the kmem_cache_* definitions
 * are removed to allow access to the real Linux slab allocator.
 */
#undef kmem_cache_destroy
#undef kmem_cache_create
#undef kmem_cache_alloc
#undef kmem_cache_free

#define LOG_PREFIX "ZFS-QAT/cy: "

qat_stats_cy_t qat_cy_stats = {

		{ "init_failed",			KSTAT_DATA_UINT64 },

		{ "sha2_256_requests",			KSTAT_DATA_UINT64 },
		{ "sha2_256_total_in_bytes",		KSTAT_DATA_UINT64 },
		{ "sha2_256_total_success_bytes",	KSTAT_DATA_UINT64 },
		{ "sha2_256_total_out_bytes",		KSTAT_DATA_UINT64 },
		{ "sha2_256_fails",			KSTAT_DATA_UINT64 },
		{ "sha2_256_throughput_bps",		KSTAT_DATA_UINT64 },
		{ "sha2_256_requests_per_second",	KSTAT_DATA_UINT64 },

#if QAT_DIGEST_ENABLE_SHA3_256

		{ "sha3_256_requests",			KSTAT_DATA_UINT64 },
		{ "sha3_256_total_in_bytes",		KSTAT_DATA_UINT64 },
		{ "sha3_256_total_success_bytes",	KSTAT_DATA_UINT64 },
		{ "sha3_256_total_out_bytes",		KSTAT_DATA_UINT64 },
		{ "sha3_256_fails",			KSTAT_DATA_UINT64 },
		{ "sha3_256_throughput_bps",		KSTAT_DATA_UINT64 },
		{ "sha3_256_requests_per_second",	KSTAT_DATA_UINT64 },

#endif

		{ "err_no_instance_available",		KSTAT_DATA_UINT64 },
		{ "err_out_of_mem",			KSTAT_DATA_UINT64 },
		{ "err_timeout",			KSTAT_DATA_UINT64 },

		// from operations
		{ "err_status_fail",                    KSTAT_DATA_UINT64 },
		{ "err_status_retry",                   KSTAT_DATA_UINT64 },
		{ "err_status_param",                   KSTAT_DATA_UINT64 },
		{ "err_status_resource",                KSTAT_DATA_UINT64 },
		{ "err_status_restarting",              KSTAT_DATA_UINT64 },
		{ "err_status_unknown",                 KSTAT_DATA_UINT64 },

};

/* visible variables */
qat_instance_info_t *instances = NULL;
atomic_t initialized = ATOMIC_INIT(0);
struct timespec engineStarted = {0};

/* local variables */
static kstat_t *qat_ksp = NULL;
static struct kmem_cache *opCache = NULL;

static atomic_t numInitFailed = ATOMIC_INIT(0);
static atomic_t instance_lock[MAX_INSTANCES] = { ATOMIC_INIT(0) };
static atomic_t current_instance_number = ATOMIC_INIT(-1);

static atomic_long_t noInstanceMessageShown = ATOMIC_LONG_INIT(0);
static atomic_long_t getInstanceMessageShown = ATOMIC_LONG_INIT(0);
static atomic_long_t getInstanceFailed = ATOMIC_LONG_INIT(0);

static spinlock_t next_instance_lock;

int
getNextInstance(const Cpa16U num_inst)
{
	int inst = 0;

	spin_lock(&next_instance_lock);
	inst = atomic_inc_return(&current_instance_number) % num_inst;
	spin_unlock(&next_instance_lock);

	return (inst);
}

CpaBoolean
check_and_lock(const Cpa16U i)
{
	CpaBoolean ret = CPA_FALSE;

	smp_mb__before_atomic();
	if (likely(0 == atomic_read(&instance_lock[i])))
	{
		atomic_inc(&instance_lock[i]);
		ret = CPA_TRUE;
	}
	smp_mb__after_atomic();

	return (ret);
}

void
unlock_instance(const Cpa16U i)
{
	smp_mb__before_atomic();
	atomic_dec(&instance_lock[i]);
	smp_mb__after_atomic();
}

/************************************
 * static kernel cache for opData
 ************************************/
CpaStatus
CREATE_OPDATA(CpaCySymDpOpData **ptr)
{
	CpaStatus status = CPA_STATUS_FAIL;

	*ptr = NULL;

	if (likely(NULL != opCache))
	{
		void *result = kmem_cache_alloc(opCache, GFP_KERNEL);
		if (likely(NULL != result))
		{
			*ptr = (CpaCySymDpOpData*)result;
			status = CPA_STATUS_SUCCESS;
		}
		else
		{
			status = CPA_STATUS_RESOURCE;
		}
	}

	return status;
}

#define DESTROY_OPDATA(pOpData) _destroy_opdata(&(pOpData))
void
_destroy_opdata(CpaCySymDpOpData **ptr)
{
	if (likely(NULL != *ptr))
	{
		if (likely(NULL != opCache))
		{
			kmem_cache_free(opCache, *ptr);
		}
		*ptr = NULL;
	}
}

/* get type of instance, polled (1) or interrupt (0) */
CpaStatus
isInstancePolled(const CpaInstanceHandle dcInstHandle, CpaBoolean *polled)
{
	CpaInstanceInfo2 *instanceInfo = NULL;
	CpaStatus status;

	status = VIRT_ALLOC(&instanceInfo, sizeof(CpaInstanceInfo2));

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		status = cpaCyInstanceGetInfo2(dcInstHandle, instanceInfo);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		*polled = instanceInfo->isPolled;
	}

	VIRT_FREE(instanceInfo);

	return status;
}

/* Warning: allocate at least CPA_INST_NAME_SIZE + 1 bytes for instance name */
CpaStatus
getInstanceName(const CpaInstanceHandle dcInstHandle, Cpa8U *instName)
{
	CpaInstanceInfo2 *instanceInfo = NULL;
	CpaStatus status;

	status = VIRT_ALLOC(&instanceInfo, sizeof(CpaInstanceInfo2));

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		status = cpaCyInstanceGetInfo2(dcInstHandle, instanceInfo);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		strncpy(instName, instanceInfo->instName, CPA_INST_NAME_SIZE);
	}

	VIRT_FREE(instanceInfo);

	return status;
}

void
qat_cy_callback_interrupt(CpaCySymDpOpData *pOpData, CpaStatus status, CpaBoolean verifyResult)
{
	if (likely(pOpData->pCallbackTag != NULL))
	{
		complete((struct completion *)pOpData->pCallbackTag);
	}
}

void
qat_cy_callback_polled(CpaCySymDpOpData *pOpData, CpaStatus status, CpaBoolean verifyResult)
{
	pOpData->pCallbackTag = (void *)1;
}

void
releaseInstanceInfo(qat_instance_info_t *info)
{
	/* Clean up */
	if (likely(info->instanceStarted))
	{
		cpaCyStopInstance(info->cyInstHandle);
	}

	info->instanceStarted = CPA_FALSE;
	info->instanceReady = CPA_FALSE;
}

CpaStatus
getReadyInstanceInfo(const CpaInstanceHandle cyInstHandle, int instNum, qat_instance_info_t *info)
{
	CpaStatus status = CPA_STATUS_FAIL;
	// CpaCyCapabilitiesInfo cap = {0};

	/* check if instance is already started and ready */
	if (info->instanceReady)
	{
		/* instance already started and ready to use,
		   just return */
		status = CPA_STATUS_SUCCESS;
	}
	else
	{
		/* Start Cryptographic instance */
		status = cpaCyStartInstance(cyInstHandle);

		if (likely(CPA_STATUS_SUCCESS == status))
		{
			info->cyInstHandle = cyInstHandle;
			info->instNum = instNum;
			info->instanceStarted = CPA_TRUE;
		}
/*
#if 0
    if (CPA_STATUS_SUCCESS == status)
    {
	status = cpaCyQueryCapabilities(cyInstHandle, &cap);
	if (CPA_STATUS_SUCCESS != status)
	{
		printk(KERN_CRIT LOG_PREFIX "failed to get instance capabilities (status=%d)\n", status);
	}
    }

    if (CPA_STATUS_SUCCESS == status) {
	if (!cap.symDpSupported)
	{
	    printk(KERN_CRIT LOG_PREFIX "unsupported functionality\n");
    	    status = CPA_STATUS_FAIL;
	}
    }
#endif
*/
		if (likely(CPA_STATUS_SUCCESS == status))
		{
			/*
			 * Set the address translation function for the instance
			 */
			status = cpaCySetAddressTranslation(cyInstHandle, (void *)virt_to_phys);
		}

		if (likely(CPA_STATUS_SUCCESS == status))
		{
			status = isInstancePolled(cyInstHandle, &info->polled);
		}

		if (likely(CPA_STATUS_SUCCESS == status))
		{
			/* Register callback function for the instance depending on polling/interrupt */
			if (likely(info->polled))
			{
				status = cpaCySymDpRegCbFunc(cyInstHandle, qat_cy_callback_polled);
			}
			else
			{
				status = cpaCySymDpRegCbFunc(cyInstHandle, qat_cy_callback_interrupt);
			}
		}

		if (likely(CPA_STATUS_SUCCESS == status))
		{
			// printk(KERN_DEBUG LOG_PREFIX "instance %d is ready\n", info->instNum);
			info->instanceReady = CPA_TRUE;
		}
	}

	return (status);
}

static void
opDataCacheConstructor(void *pOpData)
{
	memset(pOpData, 0, sizeof(CpaCySymDpOpData));
}

boolean_t
qat_cy_common_init(void)
{
	Cpa16U numInstances = 0;
	CpaStatus status = CPA_STATUS_SUCCESS;

	int qatInfoSize = MAX_INSTANCES * sizeof(qat_instance_info_t);

	status = VIRT_ALLOC(&instances, qatInfoSize);
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/* clean memory */
		memset(instances, 0, qatInfoSize);
	}
	else
	{
		printk(KERN_CRIT LOG_PREFIX "failed to allocate instance cache storage (%d)\n",
			qatInfoSize);
		goto err;
	}

	opCache = kmem_cache_create("CpaCySymDpOpData",
			sizeof(CpaCySymDpOpData),
			8, SLAB_TEMPORARY|SLAB_CACHE_DMA,
			opDataCacheConstructor);
	if (unlikely(NULL == opCache))
	{
		printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for Op Data (%ld)\n",
			sizeof(CpaCySymDpOpData));
		goto err;
	}

	/* install statistics at /proc/spl/kstat/zfs/qat-cy */
	qat_ksp = kstat_create("zfs", 0, "qat-cy", "misc",
			KSTAT_TYPE_NAMED, sizeof (qat_cy_stats) / sizeof (kstat_named_t),
			KSTAT_FLAG_VIRTUAL);

	if (unlikely(NULL == qat_ksp))
	{
		printk(KERN_CRIT LOG_PREFIX "failed to allocate statistics\n");
		goto err;
	}

	qat_ksp->ks_data = &qat_cy_stats;
	kstat_install(qat_ksp);

	spin_lock_init(&next_instance_lock);

	/* start digest service */
	if (unlikely(!qat_digest_init()))
	{
	    goto err;
	}

	getnstimeofday(&engineStarted);
	atomic_inc(&initialized);

	if (CPA_STATUS_SUCCESS == cpaCyGetNumInstances(&numInstances) && numInstances > 0)
	{
		printk(KERN_INFO LOG_PREFIX "started with %ld CY instances\n", min((long)numInstances,(long)MAX_INSTANCES));
	}
	else
	{
		printk(KERN_INFO LOG_PREFIX "initialized\n");
	}

	return B_TRUE;

err:
	printk(KERN_ALERT LOG_PREFIX "initialization failed\n");

	return B_FALSE;
}

void
qat_cy_common_fini(void)
{
	// unsigned long flags;
	int i;

	atomic_dec(&initialized);

	if (likely(NULL != instances))
	{
		for (i = 0; i < MAX_INSTANCES; i++)
		{
			releaseInstanceInfo(&instances[i]);
		}

		VIRT_FREE(instances);
	}

    	if (likely(NULL != qat_ksp))
	{
		kstat_delete(qat_ksp);
		qat_ksp = NULL;
	}

	/* initialized statically */
	DESTROY_CACHE(opCache);

	/* stop digest service */
	qat_digest_fini();

}

CpaStatus
waitForCompletion(const CpaInstanceHandle dcInstHandle, const CpaCySymDpOpData *pOpData, const CpaBoolean polled, const unsigned long timeoutMs)
{
	CpaStatus status = CPA_STATUS_SUCCESS;
	Cpa8U *instanceName = NULL;

	if (likely(polled))
	{
		/* Poll for responses. */
		const unsigned long started = jiffies;

		do
		{
			if (unlikely(jiffies_to_msecs(jiffies - started) > timeoutMs))
			{
				CpaStatus memStatus = VIRT_ALLOC(&instanceName, CPA_INST_NAME_SIZE + 1);
				if (likely(CPA_STATUS_SUCCESS == memStatus))
				{
					memset(instanceName, 0, CPA_INST_NAME_SIZE + 1);
				}

				if (likely(CPA_STATUS_SUCCESS == memStatus && CPA_STATUS_SUCCESS == getInstanceName(dcInstHandle, instanceName) && strlen(instanceName) > 0))
				{
					printk(KERN_WARNING LOG_PREFIX "instance %s: timeout over %lu ms for polled engine\n", instanceName, timeoutMs);
				}
				else
				{
					printk(KERN_WARNING LOG_PREFIX "timeout over %lu ms for polled engine\n", timeoutMs);
				}

				VIRT_FREE(instanceName);

				QAT_STAT_BUMP(err_timeout);
				status = CPA_STATUS_FAIL;
				break;
			}

			status = icp_sal_CyPollDpInstance(dcInstHandle, 1);
		}
		while (
				((CPA_STATUS_SUCCESS == status) || (CPA_STATUS_RETRY == status))
				&& (pOpData->pCallbackTag == (void *)0) );

	}
	else
	{
		struct completion *complete = (struct completion*)pOpData->pCallbackTag;

		/* we now wait until the completion of the operation using interrupts */
		if (unlikely(0 == wait_for_completion_interruptible_timeout(complete, msecs_to_jiffies(timeoutMs))))
		{
			CpaStatus memStatus = VIRT_ALLOC(&instanceName, CPA_INST_NAME_SIZE + 1);
			if (likely(CPA_STATUS_SUCCESS == memStatus))
			{
				memset(instanceName, 0, CPA_INST_NAME_SIZE + 1);
			}

			if (likely(CPA_STATUS_SUCCESS == memStatus && CPA_STATUS_SUCCESS == getInstanceName(dcInstHandle, instanceName) && strlen(instanceName) > 0))
			{
				printk(KERN_WARNING LOG_PREFIX "instance %s: timeout over %lu ms for non-polled engine\n", instanceName, timeoutMs);
			}
			else
			{
				printk(KERN_WARNING LOG_PREFIX "timeout over %lu ms for non-polled engine\n", timeoutMs);
			}

			VIRT_FREE(instanceName);

			QAT_STAT_BUMP(err_timeout);
			status = CPA_STATUS_FAIL;
		}
	}

	return status;
}

/*
 * Loading available DC instances and select next one
 */
CpaStatus
getInstance(CpaInstanceHandle *instance, int *instanceNum)
{
	CpaStatus status = CPA_STATUS_SUCCESS;
	Cpa16U num_inst = 0;
	int inst = 0;
	CpaBoolean instanceFound = CPA_FALSE;

	CpaInstanceHandle *handles = NULL;

	status = cpaCyGetNumInstances(&num_inst);
	if (unlikely(status != CPA_STATUS_SUCCESS))
	{
		// show message once in a minute
		if (jiffies_to_msecs(jiffies - atomic_long_read(&getInstanceFailed)) > 60L * 1000L)
		{
			printk(KERN_ALERT LOG_PREFIX "failed counting instances, num_failed=%d (status=%d)\n",
					atomic_read(&numInitFailed), status);
			atomic_long_set(&getInstanceFailed, jiffies);
		}
		goto done;
	}
	else
	{
		// return success but no instances configured
		if (unlikely(num_inst == 0))
		{
			// show message once in a minute
			if (jiffies_to_msecs(jiffies - atomic_long_read(&getInstanceMessageShown)) > 60L * 1000L)
			{
				printk(KERN_ALERT LOG_PREFIX "no instances found, please configure NumberCyInstances in [KERNEL_QAT] section\n");
				atomic_long_set(&getInstanceMessageShown, jiffies);
			}
			goto done;
		}
	}

	if (unlikely(num_inst > MAX_INSTANCES))
	{
		num_inst = MAX_INSTANCES;
	}

	status = VIRT_ALLOC(&handles, num_inst * sizeof(CpaInstanceHandle));
	if (unlikely(status != CPA_STATUS_SUCCESS))
	{
		printk(KERN_CRIT LOG_PREFIX "failed allocate space for instances, num_inst=%d (status=%d)\n", num_inst, status);
		goto done;
	}

	status = cpaCyGetInstances(num_inst, handles);
	if (unlikely(status != CPA_STATUS_SUCCESS))
	{
		printk(KERN_CRIT LOG_PREFIX "failed loading instances, num_inst=%d (status=%d)\n", num_inst, status);
		goto done;
	}

	for (int i = 0; i < num_inst; i++)
	{
		inst = getNextInstance(num_inst);

		if (check_and_lock(inst))
		{
			instanceFound = CPA_TRUE;
			break;
		}
	}

	if (unlikely(!instanceFound))
	{
		if (jiffies_to_msecs(jiffies - atomic_long_read(&noInstanceMessageShown)) > 60L * 1000L)
		{
			printk(KERN_WARNING LOG_PREFIX "failed to find free CY instance ouf of %d, consider to increase NumberCyInstances in [KERNEL_QAT] section\n", num_inst);
			atomic_long_set(&noInstanceMessageShown, jiffies);
		}

		status = CPA_STATUS_RESOURCE;
		QAT_STAT_BUMP(err_no_instance_available);
	}
	else
	{
		*instance = handles[inst];
		*instanceNum = inst;
	}

done:

	VIRT_FREE(handles);

	return status;
}

void
register_error_status(const CpaStatus status)
{
	switch (status)
	{
	case CPA_STATUS_FAIL:
		// Function failed.
		QAT_STAT_BUMP(err_status_fail);
		break;

	case CPA_STATUS_RETRY:
		// Resubmit the request.
		QAT_STAT_BUMP(err_status_retry);
		break;

	case CPA_STATUS_INVALID_PARAM:
		// Invalid parameter passed in.
		QAT_STAT_BUMP(err_status_param);
		break;

	case CPA_STATUS_RESOURCE:
		// Error related to system resources.
		QAT_STAT_BUMP(err_status_resource);
		break;

	case CPA_STATUS_RESTARTING:
		// API implementation is restarting. Resubmit the request.
		QAT_STAT_BUMP(err_status_restarting);
		break;

		// TODO: add more constants if any

	default:
		QAT_STAT_BUMP(err_status_unknown);
		break;
	}
}

#endif
