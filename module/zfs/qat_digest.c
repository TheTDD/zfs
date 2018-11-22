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
#include "qat_digest.h"

/*
 * Within the scope of this file file the kmem_cache_* definitions
 * are removed to allow access to the real Linux slab allocator.
 */
#undef kmem_cache_destroy
#undef kmem_cache_create
#undef kmem_cache_alloc
#undef kmem_cache_free

/*
 * Timeout - no response from hardware after 0.5 - 3 seconds
 */
#define	TIMEOUT_MS_MIN		500
#define TIMEOUT_MS_MAX		3000

/*
Depending on the specifics of the particular algorithm and QAT API parameters, a
relatively small decrease in performance may be observed for submission requests
around a buffer/packet size of 2kB to 4kB. This is expected due to optimizations in the
QAT software that can apply for requests of a certain size.
 */

#define	QAT_MIN_BUF_SIZE	(4*1024)
#define	QAT_MAX_BUF_SIZE	(128*1024)

#define LOG_PREFIX "ZFS-QAT/cy: "

/*
 * Used for qat kstat.
 */
typedef struct qat_stats
{

	/*
	 * Number of times engine is failed to initialize.
	 */
	kstat_named_t init_failed;
	/*
	 * Number of jobs submitted to qat crypto engine.
	 */
	kstat_named_t sha2_256_requests;
	/*
	 * Total bytes sent to qat crypto engine.
	 */
	kstat_named_t sha2_256_total_in_bytes;
	kstat_named_t sha2_256_total_success_bytes;
	/*
	 * Total bytes output from qat crypto engine.
	 */
	kstat_named_t sha2_256_total_out_bytes;

	/*
	 * Number of digest calculations fails in qat engine.
	 * Note: when qat fail happens, it does mean a critical hardware
	 * or software issue
	 */
	kstat_named_t sha2_256_fails;

	/* sha2-235 throughput in bytes-per-sec */
	kstat_named_t sha2_256_throughput_bps;

#if QAT_DIGEST_ENABLE_SHA3_256
	/*
	 * Number of jobs submitted to qat crypto engine.
	 */
	kstat_named_t sha3_256_requests;
	/*
	 * Total bytes sent to qat crypto engine.
	 */
	kstat_named_t sha3_256_total_in_bytes;
	kstat_named_t sha3_256_total_success_bytes;
	/*
	 * Total bytes output from qat crypto engine.
	 */
	kstat_named_t sha3_256_total_out_bytes;
	/*
	 * Number of digest calculations fails in qat engine.
	 * Note: failed decompression is the software issue or 
	 * it does mean a critical hardwar issue.
	 */
	kstat_named_t sha3_256_fails;

	/* sha3-256 throughput in bytes-per-sec */
	kstat_named_t sha3_256_throughput_bps;

#endif
	/* number of times unlocked instance was not available */
	kstat_named_t err_no_instance_available;
	kstat_named_t err_out_of_mem;

	kstat_named_t err_timeout;

	/* values of status error codes */
	kstat_named_t err_status_fail;
	kstat_named_t err_status_retry;
	kstat_named_t err_status_param;
	kstat_named_t err_status_resource;
	// kstat_named_t err_status_baddata;
	kstat_named_t err_status_restarting;
	kstat_named_t err_status_unknown;

} qat_stats_t;

qat_stats_t qat_cy_stats = {

		{ "init_failed",			KSTAT_DATA_UINT64 },

		{ "sha2_256_requests",			KSTAT_DATA_UINT64 },
		{ "sha2_256_total_in_bytes",		KSTAT_DATA_UINT64 },
		{ "sha2_256_total_success_bytes",	KSTAT_DATA_UINT64 },
		{ "sha2_256_total_out_bytes",		KSTAT_DATA_UINT64 },
		{ "sha2_256_fails",			KSTAT_DATA_UINT64 },
		{ "sha2_256_throughput_bps",		KSTAT_DATA_UINT64 },

#if QAT_DIGEST_ENABLE_SHA3_256

		{ "sha3_256_requests",			KSTAT_DATA_UINT64 },
		{ "sha3_256_total_in_bytes",		KSTAT_DATA_UINT64 },
		{ "sha3_256_total_success_bytes",	KSTAT_DATA_UINT64 },
		{ "sha3_256_total_out_bytes",		KSTAT_DATA_UINT64 },
		{ "sha3_256_fails",			KSTAT_DATA_UINT64 },
		{ "sha3_256_throughput_bps",		KSTAT_DATA_UINT64 },

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

/* maximum number of Cy-Sym instances on one QAT controller */
#define MAX_INSTANCES 128

typedef struct qat_instance_info
{
	CpaInstanceHandle cyInstHandle;
	CpaBoolean instanceStarted;
	CpaBoolean instanceReady;
	CpaBoolean polled;
	int instNum;
} qat_instance_info_t;

int zfs_qat_disable_sha2_256 = 0;
#if QAT_DIGEST_ENABLE_SHA3_256
int zfs_qat_disable_sha3_256 = 0;
#endif

static qat_instance_info_t *instances = NULL;

static kstat_t *qat_ksp = NULL;
static struct kmem_cache *opCache = NULL;
static struct kmem_cache *sessionCache = NULL;
static struct kmem_cache *bufferCache = NULL;

static atomic_t numInitFailed = ATOMIC_INIT(0);
static atomic_t initialized = ATOMIC_INIT(0);
static atomic_t instance_lock[MAX_INSTANCES] = { ATOMIC_INIT(0) };
static atomic_t current_instance_number = ATOMIC_INIT(0);

static atomic_long_t noInstanceMessageShown = ATOMIC_LONG_INIT(0);
static atomic_long_t getInstanceMessageShown = ATOMIC_LONG_INIT(0);
static atomic_long_t getInstanceFailed = ATOMIC_LONG_INIT(0);

static spinlock_t instance_storage_lock;
static spinlock_t next_instance_lock;
static rwlock_t session_cache_lock;

static spinlock_t throughput_sha2_256_lock;
static volatile struct timespec sha2_256Time = {0};

#if QAT_DIGEST_ENABLE_SHA3_256
static spinlock_t throughput_sha3_256_lock;
static volatile struct timespec sha3_256Time = {0};
#endif

#define	QAT_STAT_INCR(stat, val) \
		atomic_add_64(&qat_cy_stats.stat.value.ui64, (val));
#define	QAT_STAT_BUMP(stat) \
		QAT_STAT_INCR(stat, 1);

static inline int
getNextInstance(const Cpa16U num_inst)
{
	int inst = 0;
	// unsigned long flags;

	// spin_lock_irqsave(&next_instance_lock, flags);
	spin_lock(&next_instance_lock);
	inst = atomic_inc_return(&current_instance_number) % num_inst;
	// spin_unlock_irqrestore(&next_instance_lock, flags);
	spin_unlock(&next_instance_lock);

	return (inst);
}

static inline CpaBoolean
check_and_lock(const Cpa16U i)
{
	CpaBoolean ret = CPA_FALSE;
	// unsigned long flags;

	// spin_lock_irqsave(&instance_storage_lock, flags);
	spin_lock(&instance_storage_lock);
	if (likely(0 == atomic_read(&instance_lock[i])))
	{
		atomic_inc(&instance_lock[i]);
		ret = CPA_TRUE;
	}
	// spin_unlock_irqrestore(&instance_storage_lock, flags);
	spin_unlock(&instance_storage_lock);

	return (ret);
}

static inline void
unlock_instance(const Cpa16U i)
{
	// unsigned long flags;
	// spin_lock_irqsave(&instance_storage_lock, flags);
	spin_lock(&instance_storage_lock);
	atomic_dec(&instance_lock[i]);
	// spin_unlock_irqrestore(&instance_storage_lock, flags);
	spin_unlock(&instance_storage_lock);
}

static inline void
updateThroughputSha2_256(const uint64_t start, const uint64_t end)
{
	// unsigned long flags;
	struct timespec ts;
	jiffies_to_timespec(end - start, &ts);

	// spin_lock_irqsave(&throughput_sha2_256_lock, flags);
	spin_lock(&throughput_sha2_256_lock);

	sha2_256Time = timespec_add(sha2_256Time, ts);
	if (likely(sha2_256Time.tv_sec > 0))
	{
		const uint64_t processed = qat_cy_stats.sha2_256_total_success_bytes.value.ui64;
		atomic_swap_64(&qat_cy_stats.sha2_256_throughput_bps.value.ui64, processed / sha2_256Time.tv_sec);
	}

	// spin_unlock_irqrestore(&throughput_sha2_256_lock, flags);
	spin_unlock(&throughput_sha2_256_lock);
}

#if QAT_DIGEST_ENABLE_SHA3_256
static inline void
updateThroughputSha3_256(const uint64_t start, const uint64_t end)
{
	// unsigned long flags;
	struct timespec ts;
	jiffies_to_timespec(end - start, &ts);

	// spin_lock_irqsave(&throughput_sha3_256_lock, flags);
	spin_lock(&throughput_sha3_256_lock);

	sha3_256Time = timespec_add(sha3_256Time, ts);
	if (likely(sha3_256Time.tv_sec > 0))
	{
		const uint64_t processed = qat_cy_stats.sha3_256_total_success_bytes.value.ui64;
		atomic_swap_64(&qat_cy_stats.sha3_256_throughput_bps.value.ui64, processed / sha3_256Time.tv_sec);
	}

	// spin_unlock_irqrestore(&throughput_sha3_256_lock, flags);
	spin_unlock(&throughput_sha3_256_lock);
}
#endif

/************************************
 * dynamic kernel cache for sessions
 ************************************/
static inline CpaStatus
getReadySessionCache(const Cpa16U size)
{
	CpaStatus status = CPA_STATUS_FAIL;
	unsigned long flags;

	/* lock for reading and check */
	// read_lock_irqsave(&session_cache_lock, flags);
	read_lock(&session_cache_lock);

	if (likely(sessionCache != NULL))
	{
		status = CPA_STATUS_SUCCESS;
	}

	// read_unlock_irqrestore(&session_cache_lock, flags);
	read_unlock(&session_cache_lock);

	if (unlikely(CPA_STATUS_SUCCESS != status))
	{
		/* lock for writing and create, happens only once */
		write_lock_irqsave(&session_cache_lock, flags);

		sessionCache = kmem_cache_create("CpaCySessions",
				size, DEFAULT_ALIGN_CACHE,
				SLAB_TEMPORARY, NULL);
		if (likely(NULL != sessionCache))
		{
                       	printk(KERN_DEBUG LOG_PREFIX "create kernel cache for sessions (%d)\n", size);
			status = CPA_STATUS_SUCCESS;
		}
		else
		{
			printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for sessions (%d)\n", size);
			status = CPA_STATUS_RESOURCE;
		}

		write_unlock_irqrestore(&session_cache_lock, flags);
	}

	return status;
}

// CpaCySymSessionCtx is already a pointer
// so it will be translated to void **
static inline CpaStatus
CREATE_SESSION(CpaCySymSessionCtx *sessionCtx)
{
	CpaStatus status = CPA_STATUS_FAIL;

	*sessionCtx = NULL;

	if (likely(NULL != sessionCache))
	{
		void *result = kmem_cache_alloc(sessionCache, GFP_KERNEL);
		if (likely(NULL != result))
		{
			*sessionCtx = result;
			status = CPA_STATUS_SUCCESS;
		}
		else
		{
			status = CPA_STATUS_RESOURCE;
		}
	}

	return status;
}

#define DESTROY_SESSION(sessionCtx) _destroy_session(&(sessionCtx))
static inline void
_destroy_session(CpaCySymSessionCtx *sessionCtx)
{
	if (likely(NULL != *sessionCtx))
	{
		if (likely(NULL != sessionCache))
		{
			kmem_cache_free(sessionCache, *sessionCtx);
		}
		*sessionCtx = NULL;
	}
}

/************************************
 * static kernel cache for opData
 ************************************/
static inline CpaStatus
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
static inline void
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

/************************************
 * static kernel cache for input/output buffers
 ************************************/
static inline CpaStatus
CREATE_BUFFER(Cpa8U **ptr)
{
	CpaStatus status = CPA_STATUS_FAIL;

	*ptr = NULL;

	if (likely(NULL != bufferCache))
	{
		void *result = kmem_cache_alloc(bufferCache, GFP_KERNEL);
		if (likely(NULL != result))
		{
			*ptr = (Cpa8U*)result;
			status = CPA_STATUS_SUCCESS;
		}
		else
		{
			status = CPA_STATUS_RESOURCE;
		}
	}

	return status;
}

#define DESTROY_BUFFER(pBuffer) _destroy_buffer(&(pBuffer))
static inline void
_destroy_buffer(Cpa8U **ptr)
{
	if (likely(NULL != *ptr))
	{
		if (likely(NULL != bufferCache))
		{
			kmem_cache_free(bufferCache, *ptr);
		}
		*ptr = NULL;
	}
}

#if QAT_DIGEST_ENABLE_SHA3_256
#define MAX_DIGEST_LENGTH max((long)SHA2_256_DIGEST_LENGTH,(long)SHA3_256_DIGEST_LENGTH);
#else
#define MAX_DIGEST_LENGTH SHA2_256_DIGEST_LENGTH
#endif

static CpaStatus
isInstancePolled(const CpaInstanceHandle dcInstHandle, CpaBoolean *polled)
{
	CpaInstanceInfo2 *instanceInfo = NULL;
	CpaStatus status;

	status = VIRT_ALLOC(&instanceInfo, sizeof(CpaInstanceInfo2));

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		// get type of instance, polled (1) or interrupt (0)
		status = cpaCyInstanceGetInfo2(dcInstHandle, instanceInfo);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		*polled = instanceInfo->isPolled;
	}

	VIRT_FREE(instanceInfo);

	return status;
}

// warning: allocate at least CPA_INST_NAME_SIZE + 1 bytes for instance name
static CpaStatus
getInstanceName(const CpaInstanceHandle dcInstHandle, Cpa8U *instName)
{
	CpaInstanceInfo2 *instanceInfo = NULL;
	CpaStatus status;

	status = VIRT_ALLOC(&instanceInfo, sizeof(CpaInstanceInfo2));

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		// get name of instance
		status = cpaCyInstanceGetInfo2(dcInstHandle, instanceInfo);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		strncpy(instName, instanceInfo->instName, CPA_INST_NAME_SIZE);
	}

	VIRT_FREE(instanceInfo);

	return status;
}

static void
qat_cy_callback_interrupt(CpaCySymDpOpData *pOpData, CpaStatus status, CpaBoolean verifyResult)
{
	if (likely(pOpData->pCallbackTag != NULL))
	{
		complete((struct completion *)pOpData->pCallbackTag);
	}
}

static void
qat_cy_callback_polled(CpaCySymDpOpData *pOpData, CpaStatus status, CpaBoolean verifyResult)
{
	pOpData->pCallbackTag = (void *)1;
}

static void
releaseInstanceInfo(qat_instance_info_t *info)
{
	/* Clean up */
	if (likely(info->instanceStarted))
	{
		cpaCyStopInstance(info->cyInstHandle);
		info->instanceStarted = CPA_FALSE;
		info->instanceReady = CPA_FALSE;
	}
}

static CpaStatus
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
			printk(KERN_DEBUG LOG_PREFIX "instance %d is ready\n", info->instNum);
			info->instanceReady = CPA_TRUE;
		}
	}

	return (status);
}

static void
cacheConstructor(void *pOpData)
{
	memset(pOpData, 0, sizeof(CpaCySymDpOpData));
}

int
qat_digest_init(void)
{
	Cpa16U numInstances = 0;
	CpaStatus status = CPA_STATUS_SUCCESS;

	int qatInfoSize = MAX_INSTANCES * sizeof(qat_instance_info_t);

	status = VIRT_ALLOC(&instances, qatInfoSize);
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		// clean memory
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
			cacheConstructor);
	if (unlikely(NULL == opCache))
	{
		printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for Op Data (%ld)\n",
			sizeof(CpaCySymDpOpData));
		goto err;
	}

	bufferCache = kmem_cache_create("CpaCyBuffers",
			QAT_MAX_BUF_SIZE + MAX_DIGEST_LENGTH,
			DEFAULT_ALIGN_CACHE, SLAB_TEMPORARY, NULL);
	if (unlikely(NULL == bufferCache))
	{
		printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for input (%d)\n",
				QAT_MAX_BUF_SIZE + MAX_DIGEST_LENGTH);
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

	spin_lock_init(&throughput_sha2_256_lock);
#if QAT_DIGEST_ENABLE_SHA3_256
	spin_lock_init(&throughput_sha3_256_lock);
#endif

	spin_lock_init(&next_instance_lock);
	spin_lock_init(&instance_storage_lock);
	rwlock_init(&session_cache_lock);

	atomic_inc(&initialized);

	if (CPA_STATUS_SUCCESS == cpaCyGetNumInstances(&numInstances) && numInstances > 0)
	{
		printk(KERN_INFO LOG_PREFIX "started with %ld CY instances\n", min((long)numInstances,(long)MAX_INSTANCES));
	}
	else
	{
		printk(KERN_INFO LOG_PREFIX "initialized\n");
	}

	return 0;

err:

	printk(KERN_ALERT LOG_PREFIX "initialization failed\n");

	return 0;
}

void
qat_digest_fini(void)
{
	unsigned long flags;
	int i;

	if (likely(instances != NULL))
	{
		for (i = 0; i < MAX_INSTANCES; i++)
		{
			releaseInstanceInfo(&instances[i]);
		}

		VIRT_FREE(instances);
	}

	if (likely(NULL != qat_ksp))
	{
		atomic_dec(&initialized);

		kstat_delete(qat_ksp);
		qat_ksp = NULL;
	}

	/* initialized statically */
	DESTROY_CACHE(opCache);
	DESTROY_CACHE(bufferCache);

	/* initialized dynamically */
	write_lock_irqsave(&session_cache_lock, flags);
	DESTROY_CACHE(sessionCache);
	write_unlock_irqrestore(&session_cache_lock, flags);
}

boolean_t
qat_digest_use_accel(const qat_digest_type_t dir, const size_t s_len)
{

	boolean_t ret = B_FALSE;

	if (zfs_qat_disable == 0 && atomic_read(&initialized) > 0)
	{
		switch (dir)
		{
		case QAT_DIGEST_SHA2_256:
			ret = (0 == zfs_qat_disable_sha2_256) &&
			(QAT_MIN_BUF_SIZE <= s_len && s_len <= QAT_MAX_BUF_SIZE);
			break;

#if QAT_DIGEST_ENABLE_SHA3_256
		case QAT_DIGEST_SHA3_256:
			ret = (0 == zfs_qat_disable_sha3_256) &&
			(QAT_MIN_BUF_SIZE <= s_len && s_len <= QAT_MAX_BUF_SIZE);
			break;
#endif

		default:
			// impossible
			break;
		}
	}

	return (ret);
}

static void
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

static inline uint32_t
getTimeoutMs(const int dataSize, const int maxSize)
{
	uint32_t timeout = TIMEOUT_MS_MIN + (TIMEOUT_MS_MAX - TIMEOUT_MS_MIN) * dataSize / maxSize;
	return timeout;
}

static CpaStatus
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
static CpaStatus
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

static inline void
symSessionWaitForInflightReq(CpaCySymSessionCtx pSessionCtx)
{
	/* Session in use is available since Cryptographic API version 2.2 */
#if CY_API_VERSION_AT_LEAST(2, 2)
	CpaBoolean sessionInUse = CPA_FALSE;
	do
	{
		cpaCySymSessionInUse(pSessionCtx, &sessionInUse);
		// if (CPA_TRUE == sessionInUse) {
		//    yield();
		// }
	} while (sessionInUse);
#endif
	return;
}

static inline CpaStatus
getDigestLength(const CpaCySymHashAlgorithm algo, Cpa32U *length)
{
	CpaStatus status = CPA_STATUS_SUCCESS;

	switch (algo)
	{
	case CPA_CY_SYM_HASH_SHA256:
		*length = SHA2_256_DIGEST_LENGTH;
		break;

#if QAT_DIGEST_ENABLE_SHA3_256
	case CPA_CY_SYM_HASH_SHA3_256:
		*length = SHA3_256_DIGEST_LENGTH;
		break;
#endif

	default:
		status = CPA_STATUS_FAIL;
		break;
	}

	return status;
}

static inline void
registerIncomingRequest(const CpaCySymHashAlgorithm algo, const int src_len) {

	switch (algo) {
	case CPA_CY_SYM_HASH_SHA256:
		QAT_STAT_BUMP(sha2_256_requests);
		QAT_STAT_INCR(sha2_256_total_in_bytes, src_len);
		break;

#if QAT_DIGEST_ENABLE_SHA3_256
	case CPA_CY_SYM_HASH_SHA3_256:
		QAT_STAT_BUMP(sha3_256_requests);
		QAT_STAT_INCR(sha3_256_total_in_bytes, src_len);
		break;
#endif

	default:
		// do nothing
		break;
	}
}

static inline void
registerFailedRequest(const CpaCySymHashAlgorithm algo) {

	switch (algo)
	{
	case CPA_CY_SYM_HASH_SHA256:
		QAT_STAT_BUMP(sha2_256_fails);
		break;

#if QAT_DIGEST_ENABLE_SHA3_256
	case CPA_CY_SYM_HASH_SHA3_256:
		QAT_STAT_BUMP(sha3_256_fails);
		break;
#endif

	default:
		// do nothing
		break;
	}
}

static void
registerProcessedRequest(const CpaCySymHashAlgorithm algo, const int src_len, const int dest_len)
{
	switch (algo)
	{
	case CPA_CY_SYM_HASH_SHA256:
		QAT_STAT_INCR(sha2_256_total_success_bytes, src_len);
		QAT_STAT_INCR(sha2_256_total_out_bytes, dest_len);
		break;

#if QAT_DIGEST_ENABLE_SHA3_256
	case CPA_CY_SYM_HASH_SHA3_256:
		QAT_STAT_INCR(sha3_256_total_success_bytes, src_len);
		QAT_STAT_INCR(sha3_256_total_out_bytes, dest_len);
		break;
#endif

	default:
		// do nothing
		break;
	}
}

static qat_digest_status_t
performDigestOp(const CpaInstanceHandle cyInstHandle, const CpaCySymSessionCtx sessionCtx, const CpaBoolean polled,
		const CpaCySymHashAlgorithm algo, const uint8_t *src, const int src_len, zio_cksum_t *dest)
{
	qat_digest_status_t ret = QAT_DIGEST_FAIL;
	struct completion *pComplete = NULL;
	unsigned long timeout = 0;

	CpaStatus status;
	CpaCySymDpOpData *pOpData = NULL;
	Cpa32U digestLength = 0;
	Cpa32U bufferSize = src_len;
	Cpa8U *pSrcBuffer = NULL;

	registerIncomingRequest(algo, src_len);

	status = getDigestLength(algo, &digestLength);

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		bufferSize += digestLength;
	}

	if (unlikely(CPA_STATUS_SUCCESS == status && !polled))
	{
		status = VIRT_ALLOC(&pComplete, sizeof(struct completion));
	}

	/* Allocate Src buffer */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		// status = PHYS_CONTIG_ALLOC_ALIGNED(&pSrcBuffer, bufferSize, DEFAULT_ALIGN_ALLOC);
		status = CREATE_BUFFER(&pSrcBuffer);
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			printk(KERN_WARNING LOG_PREFIX "failed to allocate %d bytes for input buffer\n",
					bufferSize);
			QAT_STAT_BUMP(err_out_of_mem);
		}
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/* copy source into buffer */
		memcpy(pSrcBuffer, src, src_len);

		/* Allocate memory for operational data. Note this needs to be
		 * 8-byte aligned, contiguous, resident in DMA-accessible
		 * memory.
		 */
		status = CREATE_OPDATA(&pOpData);
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			printk(KERN_WARNING LOG_PREFIX "failed to allocate opData\n");
			QAT_STAT_BUMP(err_out_of_mem);
		}
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/** Populate the structure containing the operational data that is
		 * needed to run the algorithm
		 */
		pOpData->hashStartSrcOffsetInBytes = 0;
		pOpData->messageLenToHashInBytes = src_len;
		/* Even though MAC follows immediately after the region to hash
           	digestIsAppended is set to false in this case to workaround
           	errata number IXA00378322 */
		pOpData->digestResult = virt_to_phys(&pSrcBuffer[src_len]);
		pOpData->instanceHandle = cyInstHandle;
		pOpData->sessionCtx = sessionCtx;
		pOpData->srcBuffer = virt_to_phys(pSrcBuffer);
		pOpData->srcBufferLen = bufferSize;
		pOpData->dstBuffer = virt_to_phys(pSrcBuffer);
		pOpData->dstBufferLen = bufferSize;
		pOpData->thisPhys = virt_to_phys(pOpData);

		if (likely(polled))
		{
			pOpData->pCallbackTag = (void *)0;
		}
		else
		{
			init_completion(pComplete);
			pOpData->pCallbackTag = (void *)pComplete;
		}

		/** Enqueue symmetric operation */
		status = cpaCySymDpEnqueueOp(pOpData, CPA_TRUE);

		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			register_error_status(status);
			printk(KERN_CRIT LOG_PREFIX "digest job submit failed (status = %d)\n", status);
		}
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/* wait for bigger packets longer but at lease 0.5 sec */
		timeout = getTimeoutMs(src_len, QAT_MAX_BUF_SIZE);
		status = waitForCompletion(cyInstHandle, pOpData, polled, timeout);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/* copy result data from &pSrcBuffer[src_len] */
		memcpy(dest, &pSrcBuffer[src_len], digestLength);
		registerProcessedRequest(algo, src_len, digestLength);

		ret = QAT_DIGEST_SUCCESS;
	}
	else
	{
		registerFailedRequest(algo);
	}

	// PHYS_CONTIG_FREE(pSrcBuffer);
	DESTROY_BUFFER(pSrcBuffer);
	DESTROY_OPDATA(pOpData);
	VIRT_FREE(pComplete);

	return (ret);
}

static qat_digest_status_t
qat_action( qat_digest_status_t (*func)(const CpaInstanceHandle, const CpaCySymSessionCtx, const CpaBoolean, const CpaCySymHashAlgorithm, const uint8_t*, const int, zio_cksum_t *),
		const CpaCySymHashAlgorithm algo, const uint8_t* src, const int src_len, zio_cksum_t *dest)
{
	qat_digest_status_t ret = QAT_DIGEST_FAIL;
	CpaStatus status = CPA_STATUS_FAIL;
	CpaInstanceHandle cyInstHandle = NULL;
	int instNum;
	CpaCySymSessionSetupData *pSessionSetupData = NULL;
	Cpa32U digestLength = 0;
	Cpa32U sessionCtxSize;
	CpaCySymSessionCtx sessionCtx = NULL;

	/* receive locked instance, don't forget to unlock it when ready */
	status = getInstance(&cyInstHandle, &instNum);
	if (unlikely(CPA_STATUS_SUCCESS != status || NULL == cyInstHandle))
	{
		goto failed;
	}

	/* drop failure counter after successfull init */
	atomic_set(&numInitFailed, 0);

	/* initialize and start instance */
	status = getReadyInstanceInfo(cyInstHandle, instNum, &instances[instNum]);

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		status = getDigestLength(algo, &digestLength);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		status = VIRT_ALLOC(&pSessionSetupData, sizeof(CpaCySymSessionSetupData));
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		memset(pSessionSetupData, 0, sizeof(CpaCySymSessionSetupData));

		/* populate symmetric session data structure */
		pSessionSetupData->sessionPriority = CPA_CY_PRIORITY_NORMAL;
		pSessionSetupData->symOperation = CPA_CY_SYM_OP_HASH,
		pSessionSetupData->hashSetupData.hashAlgorithm = algo;
		pSessionSetupData->hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
		pSessionSetupData->hashSetupData.digestResultLenInBytes = digestLength;

		/* Even though MAC follows immediately after the region to hash
           	digestIsAppended is set to false in this case to workaround
           	errata number IXA00378322 */
		pSessionSetupData->digestIsAppended = CPA_FALSE;
		pSessionSetupData->verifyDigest = CPA_FALSE;

		/* Determine size of session context to allocate */
		status = cpaCySymSessionCtxGetDynamicSize(
				cyInstHandle, pSessionSetupData, &sessionCtxSize);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		status = getReadySessionCache(sessionCtxSize);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/* Allocate session context */
		status = CREATE_SESSION(&sessionCtx);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/* Initialize the session */
		status = cpaCySymDpInitSession(cyInstHandle, pSessionSetupData, sessionCtx);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		ret = (*func)(instances[instNum].cyInstHandle,
				sessionCtx,
				instances[instNum].polled,
				algo, src, src_len, dest);

		/* Remove the session - session init has already succeeded */

		CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

		/* Wait for inflight requests before removing session */
		symSessionWaitForInflightReq(sessionCtx);

		/* cpaCySymRemoveSession will fail if there are outstanding request for the session that the user is trying to remove */
		sessionStatus = cpaCySymDpRemoveSession(cyInstHandle, sessionCtx);

		/* maintain status of remove session only when status of all operations
		 * before it are successful. */
		if (likely(CPA_STATUS_SUCCESS == status))
		{
			status = sessionStatus;
		}
	}

	/* Free session setup */
	VIRT_FREE(pSessionSetupData);

	/* Free session Context */
	DESTROY_SESSION(sessionCtx);

	/* to get more free memory unlock instance after cleaning */
	unlock_instance(instNum);

	return (ret);

// go here before any initializations
failed:

	QAT_STAT_BUMP(init_failed);
	int failed = atomic_inc_return(&numInitFailed);

	if (zfs_qat_init_failure_threshold > 0 && failed >= zfs_qat_init_failure_threshold)
	{
		printk(KERN_ALERT LOG_PREFIX "disabled because number of failed initializations %d is equal or greater then threshold %d\n",
				failed, zfs_qat_init_failure_threshold);

		zfs_qat_disable_sha2_256 = 1;
#if QAT_DIGEST_ENABLE_SHA3_256
		zfs_qat_disable_sha3_256 = 1;
#endif
	}

	return (ret);
}

/*************************************************************************
 *
 * QAT digest entry point
 *
 *************************************************************************/
qat_digest_status_t
qat_digest(const qat_digest_type_t type, const uint8_t *src, const int src_len, zio_cksum_t *dest)
{
	qat_digest_status_t ret = QAT_DIGEST_FAIL;

	const unsigned long start = jiffies;

	switch (type)
	{
	case QAT_DIGEST_SHA2_256:
		// printk(KERN_DEBUG LOG_PREFIX "just info, requested to SHA2-256 %d bytes\n", src_len);
		ret = qat_action(performDigestOp, CPA_CY_SYM_HASH_SHA256, src, src_len, dest);
		if (likely(QAT_DIGEST_SUCCESS == ret))
		{
			updateThroughputSha2_256(start, jiffies);
		}
		break;

#if QAT_DIGEST_ENABLE_SHA3_256
	case QAT_DIGEST_SHA3_256:
		// printk(KERN_DEBUG LOG_PREFIX "just info, requested to SHA3-256 %d bytes\n", src_len);
		ret = qat_action(performDigestOp, CPA_CY_SYM_HASH_SHA3_256, src, src_len, dest);
		if (likely(QAT_DIGEST_SUCCESS == ret))
		{
			updateThroughputSha3_256(start, jiffies);
		}
		break;
#endif

	default:
		// not possible
		break;
	}

	return ret;
}


module_param(zfs_qat_disable_sha2_256, int, 0644);
MODULE_PARM_DESC(zfs_qat_disable_sha2_256, "Disable SHA2-256 digest calculations");

#if QAT_DIGEST_ENABLE_SHA3_256
module_param(zfs_qat_disable_sha3_256, int, 0644);
MODULE_PARM_DESC(zfs_qat_disable_sha3_256, "Disable SHA3-256 digest calculations");
#endif

#endif
