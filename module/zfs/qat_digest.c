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
#include "qat_digest.h"

/*
 * Within the scope of this file file the kmem_cache_* definitions
 * are removed to allow access to the real Linux slab allocator.
 */
#undef kmem_cache_destroy
#undef kmem_cache_create
#undef kmem_cache_alloc
#undef kmem_cache_free

#define LOG_PREFIX "ZFS-QAT/digest: "

/*
Depending on the specifics of the particular algorithm and QAT API parameters, a
relatively small decrease in performance may be observed for submission requests
around a buffer/packet size of 2kB to 4kB. This is expected due to optimizations in the
QAT software that can apply for requests of a certain size.
 */

#define	QAT_MIN_BUF_SIZE	(4*1024)
#define	QAT_MAX_BUF_SIZE	(128*1024)

int zfs_qat_disable_checksum_benchmark = 0;
int zfs_qat_disable_sha2_256 = 0;
#if QAT_DIGEST_ENABLE_SHA3_256
int zfs_qat_disable_sha3_256 = 0;
#endif

static struct kmem_cache *sessionCache = NULL;
static struct kmem_cache *bufferCache = NULL;

static rwlock_t session_cache_lock;

static atomic_t numInitFailed = ATOMIC_INIT(0);

static spinlock_t throughput_sha2_256_lock;
static volatile struct timespec sha2_256Time = {0};

#if QAT_DIGEST_ENABLE_SHA3_256
static spinlock_t throughput_sha3_256_lock;
static volatile struct timespec sha3_256Time = {0};
#endif

static inline void
updateThroughputSha2_256(const uint64_t start, const uint64_t end)
{
	struct timespec ts;
	struct timespec now;
	struct timespec diff;

	getnstimeofday(&now);
	diff = timespec_sub(now, engineStarted);

	jiffies_to_timespec(end - start, &ts);

	spin_lock(&throughput_sha2_256_lock);

	sha2_256Time = timespec_add(sha2_256Time, ts);
	if (likely(sha2_256Time.tv_sec > 0))
	{
		const uint64_t processed = qat_cy_stats.sha2_256_total_success_bytes.value.ui64;
		qat_cy_stats.sha2_256_throughput_bps.value.ui64 = processed / sha2_256Time.tv_sec;
	}
	if (likely(diff.tv_sec > 0))
	{
		qat_cy_stats.sha2_256_requests_per_second.value.ui64 =
			qat_cy_stats.sha2_256_requests.value.ui64 / diff.tv_sec;
	}

	spin_unlock(&throughput_sha2_256_lock);
}

#if QAT_DIGEST_ENABLE_SHA3_256
static inline void
updateThroughputSha3_256(const uint64_t start, const uint64_t end)
{
	struct timespec ts;
	struct timespec diff;

	getnstimeofday(&now);
	diff = timespec_sub(now, engineStarted);

	jiffies_to_timespec(end - start, &ts);

	spin_lock(&throughput_sha3_256_lock);

	sha3_256Time = timespec_add(sha3_256Time, ts);
	if (likely(sha3_256Time.tv_sec > 0))
	{
		const uint64_t processed = qat_cy_stats.sha3_256_total_success_bytes.value.ui64;
		qat_cy_stats.sha3_256_throughput_bps.value.ui64 =
			processed / sha3_256Time.tv_sec;
	}
	if (likely(diff.tv_sec > 0))
	{
		qat_cy_stats.sha3_256_requests_per_second.value.ui64 =
			qat_cy_stats.sha3_256_requests.value.ui64 / diff.tv_sec;
	}

	spin_unlock(&throughput_sha3_256_lock);
}
#endif

/************************************
 * dynamic kernel cache for sessions
 ************************************/
CpaStatus
getReadySessionCache(const Cpa16U size)
{
	CpaStatus status = CPA_STATUS_FAIL;
	unsigned long flags;

	/* lock for reading and check */
	read_lock(&session_cache_lock);

	if (likely(sessionCache != NULL))
	{
		status = CPA_STATUS_SUCCESS;
	}

	read_unlock(&session_cache_lock);

	if (unlikely(CPA_STATUS_SUCCESS != status))
	{
		/* lock for writing and create, happens only once */
		write_lock_irqsave(&session_cache_lock, flags);

		sessionCache = kmem_cache_create("CpaDigestSessions",
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

/*
  CpaCySymSessionCtx is already a pointer
  so it will be translated to void **
*/
CpaStatus
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
void
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

boolean_t
qat_digest_init(void)
{
	bufferCache = kmem_cache_create("CpaDigestBuffers",
			QAT_MAX_BUF_SIZE + MAX_DIGEST_LENGTH,
			DEFAULT_ALIGN_CACHE, SLAB_TEMPORARY, NULL);
	if (unlikely(NULL == bufferCache))
	{
		printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for input (%d)\n",
				QAT_MAX_BUF_SIZE + MAX_DIGEST_LENGTH);
		goto err;
	}

	rwlock_init(&session_cache_lock);

	spin_lock_init(&throughput_sha2_256_lock);
#if QAT_DIGEST_ENABLE_SHA3_256
	spin_lock_init(&throughput_sha3_256_lock);
#endif

	return B_TRUE;

err:

	printk(KERN_ALERT LOG_PREFIX "initialization failed\n");

	return B_FALSE;
}

void
qat_digest_fini(void)
{
	unsigned long flags;
    
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
performDigestOp(qat_instance_info_t *info, const CpaCySymSessionCtx sessionCtx,
		const CpaCySymHashAlgorithm algo, const uint8_t *src, const int src_len, zio_cksum_t *dest)
{
	qat_digest_status_t ret = QAT_DIGEST_FAIL;
	struct completion *pComplete = NULL;
	unsigned long timeout = 0;

	const CpaInstanceHandle cyInstHandle = info->cyInstHandle;
	const CpaBoolean polled = info->polled;

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
qat_action( qat_digest_status_t (*func)(qat_instance_info_t*, const CpaCySymSessionCtx, const CpaCySymHashAlgorithm, const uint8_t*, const int, zio_cksum_t *),
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
		ret = (*func)(&instances[instNum],
				sessionCtx,
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

		ret = qat_action(performDigestOp, CPA_CY_SYM_HASH_SHA256, src, src_len, dest);
		if (likely(QAT_DIGEST_SUCCESS == ret))
		{
			if (0 == zfs_qat_disable_checksum_benchmark)
			{
				updateThroughputSha2_256(start, jiffies);
			}
		}
		break;

#if QAT_DIGEST_ENABLE_SHA3_256
	case QAT_DIGEST_SHA3_256:

		ret = qat_action(performDigestOp, CPA_CY_SYM_HASH_SHA3_256, src, src_len, dest);
		if (likely(QAT_DIGEST_SUCCESS == ret))
		{
			if (0 == zfs_qat_disable_checksum_benchmark)
			{
				updateThroughputSha3_256(start, jiffies);
			}
		}
		break;
#endif

	default:
		// not possible
		break;
	}

	return ret;
}

module_param(zfs_qat_disable_checksum_benchmark, int, 0644);
MODULE_PARM_DESC(zfs_qat_disable_checksum_benchmark, "Disable benchmark of checksum calculations");

module_param(zfs_qat_disable_sha2_256, int, 0644);
MODULE_PARM_DESC(zfs_qat_disable_sha2_256, "Disable SHA2-256 digest calculations");

#if QAT_DIGEST_ENABLE_SHA3_256
module_param(zfs_qat_disable_sha3_256, int, 0644);
MODULE_PARM_DESC(zfs_qat_disable_sha3_256, "Disable SHA3-256 digest calculations");
#endif

#endif
