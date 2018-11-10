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
#include <lac/cpa_cy_im.h>
#include <lac/cpa_cy_sym_dp.h>
#include <icp_sal_poll.h>

#include "qat_common.h"
#include "qat_digest.h"

/*
 * Timeout - no response from hardware after 0.5 - 5 seconds
 */
#define	TIMEOUT_MS_MIN		500
#define TIMEOUT_MS_MAX		5000

#define	QAT_MIN_BUF_SIZE	(2*1024)
#define	QAT_MAX_BUF_SIZE	(1024*1024)

#define LOG_PREFIX "ZFS-QAT/cy: "

/*
 * Used for qat kstat.
 */
typedef struct qat_stats {

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

	kstat_named_t sha3_256_throughput_bps;

#endif
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
	{ "err_timeout",			KSTAT_DATA_UINT64 },

	// from operations
        { "err_status_fail",                    KSTAT_DATA_UINT64 },
        { "err_status_retry",                   KSTAT_DATA_UINT64 },
        { "err_status_param",                   KSTAT_DATA_UINT64 },
        { "err_status_resource",                KSTAT_DATA_UINT64 },
        // { "err_status_baddata",                 KSTAT_DATA_UINT64 },
        { "err_status_restarting",              KSTAT_DATA_UINT64 },
        { "err_status_unknown",                 KSTAT_DATA_UINT64 },

};

static kstat_t *qat_ksp;

int zfs_qat_disable_sha2_256 = 0;
#if QAT_DIGEST_ENABLE_SHA3_256
int zfs_qat_disable_sha3_256 = 0;
#endif

static atomic_t numInitFailed = ATOMIC_INIT(0);
static atomic_t instNum = ATOMIC_INIT(0);

static volatile uint64_t sha2_256TimeUs = 0;
#if QAT_DIGEST_ENABLE_SHA3_256
static volatile uint64_t sha3_256TimeUs = 0;
#endif

#define	QAT_STAT_INCR(stat, val) \
	atomic_add_64(&qat_cy_stats.stat.value.ui64, (val));
#define	QAT_STAT_BUMP(stat) \
	QAT_STAT_INCR(stat, 1);

#define USEC_IN_SEC	1000000UL

static inline void 
updateThroughputSha2_256(const uint64_t start, const uint64_t end) {
    const unsigned long us = jiffies_to_usecs(end - start);
    const uint64_t time = atomic_add_64_nv(&sha2_256TimeUs, us);
    if (time > 0) {
        const uint64_t processed = qat_cy_stats.sha2_256_total_success_bytes.value.ui64;
	if (processed > 0) {
    	    atomic_swap_64(&qat_cy_stats.sha2_256_throughput_bps.value.ui64, USEC_IN_SEC * processed / time);
    	}
    }
}

#if QAT_DIGEST_ENABLE_SHA3_256
static inline void 
updateThroughputSha3_256(const uint64_t start, const uint64_t end) {
    const unsigned long us = jiffies_to_usecs(end - start);
    const uint64_t time = atomic_add_64_nv(&sha3_256TimeUs, us);
    if (time > 0) {
	const uint64_t processed = qat_cy_stats.sha3_256_total_success_bytes.value.ui64;
	if (processed > 0) {
    	    atomic_swap_64(&qat_cy_stats.sha3_256_throughput_bps.value.ui64, USEC_IN_SEC * processed / time);
    	}
    }
}
#endif

int
qat_digest_init(void)
{

	Cpa16U numInstances = 0;

	qat_ksp = kstat_create("zfs", 0, "qat-cy", "misc",
	    KSTAT_TYPE_NAMED, sizeof (qat_cy_stats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (qat_ksp != NULL) 
	{
		qat_ksp->ks_data = &qat_cy_stats;
		kstat_install(qat_ksp);
	}

	if (CPA_STATUS_SUCCESS == cpaCyGetNumInstances(&numInstances) && numInstances > 0)
	{
	    printk(KERN_INFO LOG_PREFIX "started with %d CY instances\n", numInstances);
	}
	else
	{
	    printk(KERN_INFO LOG_PREFIX "initialized\n");
	}

	return 0;
}

void
qat_digest_fini(void)
{
	if (qat_ksp != NULL) 
	{
		kstat_delete(qat_ksp);
		qat_ksp = NULL;
	}
}

boolean_t
qat_digest_use_accel(const qat_digest_type_t dir, const size_t s_len)
{

    boolean_t ret = B_FALSE;

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
	    break;;
    }

    return (ret);

}

static void 
register_error_status(const CpaStatus status) {

    switch (status) {
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

static void
qat_cy_callback_interrupt(CpaCySymDpOpData *pOpData, CpaStatus status, CpaBoolean verifyResult)
{
    if (pOpData->pCallbackTag != NULL) {
        complete((struct completion *)pOpData->pCallbackTag);
    }
}

static void
qat_cy_callback_polled(CpaCySymDpOpData *pOpData, CpaStatus status, CpaBoolean verifyResult)
{
    pOpData->pCallbackTag = (void *)1;
}

static inline unsigned long
getTimeoutMs(const int dataSize, const int maxSize) 
{

    unsigned long timeout = TIMEOUT_MS_MIN + (TIMEOUT_MS_MAX - TIMEOUT_MS_MIN) * dataSize / maxSize;
    return timeout;

}

static CpaStatus
isInstancePolled(const CpaInstanceHandle dcInstHandle, boolean_t *polled) 
{

    CpaInstanceInfo2 *instanceInfo = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (CPA_STATUS_SUCCESS == status) 
    {
	status = VIRT_ALLOC(&instanceInfo,sizeof(CpaInstanceInfo2));
    }

    if (CPA_STATUS_SUCCESS == status) 
    {
	// get type of instance, polled (1) or interrupt (0)
	status = cpaCyInstanceGetInfo2(dcInstHandle, instanceInfo);
	if (CPA_STATUS_SUCCESS == status) 
	{
	    *polled = instanceInfo->isPolled;
	}
    }

    VIRT_FREE(instanceInfo);

    return status;
}

// warning: allocate at least CPA_INST_NAME_SIZE + 1 bytes for instance name
static CpaStatus
getInstanceName(const CpaInstanceHandle dcInstHandle, Cpa8U *instName) 
{

    CpaInstanceInfo2 *instanceInfo = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (CPA_STATUS_SUCCESS == status)
    {
	status = VIRT_ALLOC(&instanceInfo, sizeof(CpaInstanceInfo2));
    }

    if (CPA_STATUS_SUCCESS == status) 
    {
        // get name of instance
	status = cpaCyInstanceGetInfo2(dcInstHandle, instanceInfo);
	if (CPA_STATUS_SUCCESS == status) 
	{
	    strncpy(instName, instanceInfo->instName, CPA_INST_NAME_SIZE);
	}
    }

    VIRT_FREE(instanceInfo);

    return status;
}

static CpaStatus
waitForCompletion(const CpaInstanceHandle dcInstHandle, const CpaCySymDpOpData *pOpData, const boolean_t polled, const unsigned long timeoutMs) 
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *instanceName = NULL; 

    if (polled) 
    {
	/* Poll for responses.
         * Polling functions are implementation specific */
	const unsigned long started = jiffies;
	
    	do
    	{
    	    if (jiffies_to_msecs(jiffies - started) > timeoutMs)
    	    {
		CpaStatus memStatus = VIRT_ALLOC(&instanceName, CPA_INST_NAME_SIZE + 1);
		if (CPA_STATUS_SUCCESS == memStatus) 
		{
		    memset(instanceName, 0, CPA_INST_NAME_SIZE + 1);
		}

		if (CPA_STATUS_SUCCESS == memStatus && CPA_STATUS_SUCCESS == getInstanceName(dcInstHandle, instanceName) && strlen(instanceName) > 0) 
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

	    yield();

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
    	if (!wait_for_completion_interruptible_timeout(complete, msecs_to_jiffies(timeoutMs))) 
    	{

	    CpaStatus memStatus = VIRT_ALLOC(&instanceName, CPA_INST_NAME_SIZE + 1);
	    if (CPA_STATUS_SUCCESS == memStatus) 
	    {
		memset(instanceName, 0, CPA_INST_NAME_SIZE + 1);
	    }

	    if (CPA_STATUS_SUCCESS == memStatus && CPA_STATUS_SUCCESS == getInstanceName(dcInstHandle, instanceName) && strlen(instanceName) > 0) 
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
getInstance(CpaInstanceHandle *instance) 
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa16U num_inst = 0;
    int i = 0;

    CpaInstanceHandle *handles = NULL;

    status = cpaCyGetNumInstances(&num_inst);
    if (status != CPA_STATUS_SUCCESS || num_inst == 0) 
    {
            printk(KERN_ALERT LOG_PREFIX "failed counting instances, num_inst=%d, num_failed=%d (status=%d)\n",
                    num_inst, atomic_read(&numInitFailed), status);
            goto done;
    }

    status = VIRT_ALLOC(&handles, num_inst * sizeof(CpaInstanceHandle));
    if (status != CPA_STATUS_SUCCESS) 
    {
            printk(KERN_CRIT LOG_PREFIX "failed allocate space for instances, num_inst=%d (status=%d)\n", num_inst, status);
            goto done;
    }

    status = cpaCyGetInstances(num_inst, handles);
    if (status != CPA_STATUS_SUCCESS) 
    {
            printk(KERN_CRIT LOG_PREFIX "failed loading instances, num_inst=%d (status=%d)\n", num_inst, status);
            goto done;
    }

    smp_mb__before_atomic();
    i = atomic_inc_return(&instNum) % num_inst;
    smp_mb__after_atomic();

    *instance = handles[i];

done:

    VIRT_FREE(handles);

    return status;

}

void symSessionWaitForInflightReq(CpaCySymSessionCtx pSessionCtx)
{

/* Session reuse is available since Cryptographic API version 2.2 */
#if CY_API_VERSION_AT_LEAST(2, 2)
    CpaBoolean sessionInUse = CPA_FALSE;
    do
    {
        cpaCySymSessionInUse(pSessionCtx, &sessionInUse);
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

static void
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

static void
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
registerProcessedRequest(const CpaCySymHashAlgorithm algo, const int src_len, const int dest_len) {

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
performDigestOp(const CpaInstanceHandle cyInstHandle, const CpaCySymSessionCtx sessionCtx, const boolean_t polled,
    const CpaCySymHashAlgorithm algo, const uint8_t *src, const int src_len, zio_cksum_t *dest) 
{
     qat_digest_status_t ret = QAT_DIGEST_FAIL;
     struct completion *pComplete = NULL;
     unsigned long timeout = 0;

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymDpOpData *pOpData = NULL;
    Cpa32U digestLength = 0; 
    Cpa32U bufferSize = src_len;
    Cpa8U *pSrcBuffer = NULL;

    registerIncomingRequest(algo, src_len);

    status = getDigestLength(algo, &digestLength);
    
    if (CPA_STATUS_SUCCESS == status)
    {
	bufferSize += digestLength;
    }

    if (CPA_STATUS_SUCCESS == status && !polled) 
    {
	status = VIRT_ALLOC(&pComplete, sizeof(struct completion));
    }

    /* Allocate Src buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
    	status = PHYS_CONTIG_ALLOC(&pSrcBuffer, bufferSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* copy source into buffer */
        memcpy(pSrcBuffer, src, src_len);

        /* Allocate memory for operational data. Note this needs to be
         * 8-byte aligned, contiguous, resident in DMA-accessible
         * memory.
         */
        status =
            PHYS_CONTIG_ALLOC_ALIGNED(&pOpData, sizeof(CpaCySymDpOpData), 8);
    }

    if (CPA_STATUS_SUCCESS == status)
    {

	memset(pOpData, 0, sizeof(CpaCySymDpOpData));

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

	if (polled) 
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

	if (CPA_STATUS_SUCCESS != status)
	{
    	    register_error_status(status);
            printk(KERN_CRIT LOG_PREFIX "digest job submit failed (status = %d)\n", status);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
	// wait for bigger packets longer but at lease 0.5 sec
        timeout = getTimeoutMs(src_len, QAT_MAX_BUF_SIZE);

	status = waitForCompletion(cyInstHandle, pOpData, polled, timeout);
    }

    /* Check result */
    if (CPA_STATUS_SUCCESS == status)
    {

	// copy data from &pSrcBuffer[src_len]
	memcpy(dest, &pSrcBuffer[src_len], digestLength);
	registerProcessedRequest(algo, src_len, digestLength);
	
	ret = QAT_DIGEST_SUCCESS;
    }
    else
    {
	registerFailedRequest(algo);
    }

    PHYS_CONTIG_FREE(pSrcBuffer);
    PHYS_CONTIG_FREE(pOpData);
    VIRT_FREE(pComplete);

    return (ret);
}


static qat_digest_status_t
qat_action( qat_digest_status_t (*func)(const CpaInstanceHandle, const CpaCySymSessionCtx, const boolean_t, const CpaCySymHashAlgorithm, const uint8_t*, const int, zio_cksum_t *),
    const CpaCySymHashAlgorithm algo, const uint8_t* src, const int src_len, zio_cksum_t *dest)
{
    qat_digest_status_t ret = QAT_DIGEST_FAIL;

    CpaStatus status = CPA_STATUS_FAIL;
    CpaCySymSessionCtx sessionCtx = NULL;
    Cpa32U sessionCtxSize = 0;
    CpaInstanceHandle cyInstHandle = NULL;
    CpaCySymSessionSetupData *pSessionSetupData = NULL;
    // CpaCyCapabilitiesInfo cap = {0};

    boolean_t polled = B_FALSE;
    Cpa32U digestLength = 0;

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a crypto service.
     */
    status = getInstance(&cyInstHandle);
    if (CPA_STATUS_SUCCESS != status || cyInstHandle == NULL)
    {
        goto failed;
    }

    // drop counter after successfull init
    atomic_set(&numInitFailed, 0);

    /* Start Cryptographic component */
    if (CPA_STATUS_SUCCESS == status) 
    {
	status = cpaCyStartInstance(cyInstHandle);
    }

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

    if (CPA_STATUS_SUCCESS == status) 
    {
	status = isInstancePolled(cyInstHandle, &polled);
    }

    if (CPA_STATUS_SUCCESS == status) 
    {
        /*
         * Set the address translation function for the instance
         */
        status = cpaCySetAddressTranslation(cyInstHandle, (void *)virt_to_phys);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Register callback function for the instance */
        if (polled) 
	{
	    status = cpaCySymDpRegCbFunc(cyInstHandle, qat_cy_callback_polled);
	} 
	else 
	{
	    status = cpaCySymDpRegCbFunc(cyInstHandle, qat_cy_callback_interrupt);
        }
    }
    
    if (CPA_STATUS_SUCCESS == status) 
    {
	status = getDigestLength(algo, &digestLength);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
	status = VIRT_ALLOC(&pSessionSetupData, sizeof(CpaCySymSessionSetupData));
    }

    if (CPA_STATUS_SUCCESS == status)
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
        status = cpaCySymDpSessionCtxGetSize(
            cyInstHandle, pSessionSetupData, &sessionCtxSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate session context */
        status = PHYS_CONTIG_ALLOC(&sessionCtx, sessionCtxSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Initialize the session */
        status = cpaCySymDpInitSession(cyInstHandle, pSessionSetupData, sessionCtx);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform algchaining operation */
        ret = (*func)(cyInstHandle, sessionCtx, polled, algo, src, src_len, dest);

        /* Remove the session - session init has already succeeded */

        /* Wait for inflight requests before removing session */
        symSessionWaitForInflightReq(sessionCtx);

        sessionStatus = cpaCySymDpRemoveSession(cyInstHandle, sessionCtx);

        /* maintain status of remove session only when status of all operations
         * before it are successful. */
        if (CPA_STATUS_SUCCESS == status)
        {
            status = sessionStatus;
        }
    }

    /* Clean up */

    VIRT_FREE(pSessionSetupData);

    /* Free session Context */
    PHYS_CONTIG_FREE(sessionCtx);

    cpaCyStopInstance(cyInstHandle);

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
	    // printk(KERN_ALERT LOG_PREFIX "just info, requested to compress %d bytes to buffer size %d\n", src_len, dest_len);
            ret = qat_action(performDigestOp, CPA_CY_SYM_HASH_SHA256, src, src_len, dest);
	    if (QAT_DIGEST_SUCCESS == ret)
	    {
		updateThroughputSha2_256(start, jiffies);
	    }
            break;

#if QAT_DIGEST_ENABLE_SHA3_256
        case QAT_DIGEST_SHA3_256:
	    // printk(KERN_ALERT LOG_PREFIX "just info, requested to decompress %d bytes to buffer size %d\n", src_len, dest_len);
            ret = qat_action(performDigestOp, CPA_CY_SYM_HASH_SHA3_256, src, src_len, dest);
	    if (QAT_DIGEST_SUCCESS == ret)
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
