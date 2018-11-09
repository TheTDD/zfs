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
#include <dc/cpa_dc_dp.h>
#include <icp_sal_poll.h>

#include "qat_common.h"
#include "qat_compress.h"
#include "qat_cnv_utils.h"

/*
 * Timeout - no response from hardware after 0.5 - 5 seconds
 */
#define	TIMEOUT_MS_MIN		500
#define TIMEOUT_MS_MAX		5000

/*
 * ZLIB head and foot size
 */
#define	ZLIB_HEAD_SZ		2
#define	ZLIB_FOOT_SZ		4

/*
 * The minimal and maximal buffer size, which are not restricted
 * in the QAT hardware, but with the input buffer size between 4KB
 * and 128KB, the hardware can provide the optimal performance.
 *
 * This shows the better compression ratio of QAT over zlib
 * is by chunk sizes 2K to 128K
 * https://01.org/sites/default/files/page/332125_002_0.pdf
 * Using Intel ® QuickAssist Technology, the optimal buffer size to offload is found to
 * be around 64-128 KB. Larger buffers (e.g., >128 KB) can yield sub-optimal Huffman
 * trees, leading to a poorer compression ratio.
 */

#define	QAT_MIN_BUF_SIZE	(2*1024)
#define	QAT_MAX_BUF_SIZE_COMP	(128*1024)
#define QAT_MAX_BUF_SIZE_DECOMP (1024*1024)

#define LOG_PREFIX "ZFS-QAT/dc: "

/*
 * Used for qat kstat.
 */
typedef struct qat_stats {

	/*
	 * Number of times engine is failed to initialize.
	 */
	kstat_named_t init_failed;
	/*
	 * Number of jobs submitted to qat compression engine.
	 */
	kstat_named_t comp_requests;
	/*
	 * Total bytes sent to qat compression engine.
	 */
	kstat_named_t comp_total_in_bytes;
	/*
	 * Total bytes output from qat compression engine.
	 */
	kstat_named_t comp_total_out_bytes;

	/*
	 * Number of compression fails in qat engine.
	 * Note: when qat fail happens, it doesn't mean a critical hardware
	 * issue, sometimes it is because the output buffer is not big enough,
	 * and the compression job will be transfered to gzip software again,
	 * so the functionality of ZFS is not impacted.
	 */
	kstat_named_t comp_fails;

	/*
	 * Number of jobs submitted to qat de-compression engine.
	 */
	kstat_named_t decomp_requests;
	/*
	 * Total bytes sent to qat de-compression engine.
	 */
	kstat_named_t decomp_total_in_bytes;
	/*
	 * Total bytes output from qat de-compression engine.
	 */
	kstat_named_t decomp_total_out_bytes;
	/*
	 * Number of decompression fails in qat engine.
	 * Note: failed decompression is the software issue or 
	 * it does mean a critical hardwar issue.
	 */
	kstat_named_t decomp_fails;

	/* number of times engine failed to generate ZLIB header */
	kstat_named_t err_gen_header;
	/* number of time engine failed to perform the operation in time */
	kstat_named_t err_timeout;
	/* number of times engine failed to generate ZLIB footer */
    	kstat_named_t err_gen_footer;
	/* number of times the engine found uncompressible data or decompression issue */
	kstat_named_t err_overflow;;

	/* values of status error codes */
	kstat_named_t err_status_fail;
	kstat_named_t err_status_retry;
	kstat_named_t err_status_param;
	kstat_named_t err_status_resource;
	kstat_named_t err_status_baddata;
	kstat_named_t err_status_restarting;
	kstat_named_t err_status_unknown;

	/* values of pOpData->results.status error codes */
	kstat_named_t err_op_overflow;
	kstat_named_t err_op_hw;
	kstat_named_t err_op_sw;
	kstat_named_t err_op_fatal;
	kstat_named_t err_op_unknown;

	kstat_named_t throughput_comp_bps;
	kstat_named_t throughput_decomp_bps;
	
} qat_stats_t;

qat_stats_t qat_dc_stats = {
	{ "init_failed",			KSTAT_DATA_UINT64 },

	{ "comp_requests",			KSTAT_DATA_UINT64 },
	{ "comp_total_in_bytes",		KSTAT_DATA_UINT64 },
	{ "comp_total_out_bytes",		KSTAT_DATA_UINT64 },
	{ "comp_fails",				KSTAT_DATA_UINT64 },

	{ "decomp_requests",			KSTAT_DATA_UINT64 },
	{ "decomp_total_in_bytes",		KSTAT_DATA_UINT64 },
	{ "decomp_total_out_bytes",		KSTAT_DATA_UINT64 },
	{ "decomp_fails",			KSTAT_DATA_UINT64 },

	{ "err_gen_header",                     KSTAT_DATA_UINT64 },
        { "err_timeout",                        KSTAT_DATA_UINT64 },
        { "err_gen_footer",                     KSTAT_DATA_UINT64 },
	{ "err_overflow",                 	KSTAT_DATA_UINT64 },

	// from operations
        { "err_status_fail",                    KSTAT_DATA_UINT64 },
        { "err_status_retry",                   KSTAT_DATA_UINT64 },
        { "err_status_param",                   KSTAT_DATA_UINT64 },
        { "err_status_resource",                KSTAT_DATA_UINT64 },
        { "err_status_baddata",                 KSTAT_DATA_UINT64 },
        { "err_status_restarting",              KSTAT_DATA_UINT64 },
        { "err_status_unknown",                 KSTAT_DATA_UINT64 },

	// from comression/decompression results
        { "err_op_overflow",                    KSTAT_DATA_UINT64 },
        { "err_op_hw",                          KSTAT_DATA_UINT64 },
        { "err_op_sw",                          KSTAT_DATA_UINT64 },
        { "err_op_fatal",                       KSTAT_DATA_UINT64 },
	{ "err_op_unknown",                     KSTAT_DATA_UINT64 },

	{ "throughput_comp_bps",		KSTAT_DATA_UINT64 },
	{ "throughput_decomp_bps",		KSTAT_DATA_UINT64 },
	
};

static kstat_t *qat_ksp;

int zfs_qat_disable_compression = 0;
int zfs_qat_disable_decompression = 0;

static atomic_t numInitFailed = ATOMIC_INIT(0);
static atomic_t instNum = ATOMIC_INIT(0);

static volatile uint64_t compressionTimeMs = 0;
static volatile uint64_t decompressionTimeMs = 0;

#define	QAT_STAT_INCR(stat, val) \
	atomic_add_64(&qat_dc_stats.stat.value.ui64, (val));
#define	QAT_STAT_BUMP(stat) \
	QAT_STAT_INCR(stat, 1);

static inline void 
updateThroughputComp(const uint64_t start, const uint64_t end) {
    const unsigned long ms = jiffies_to_msecs(end - start);
    const uint64_t time = atomic_add_64_nv(&compressionTimeMs, ms);
    if (time > 0) {
        const uint64_t processed = qat_dc_stats.comp_total_out_bytes.value.ui64;
	atomic_swap_64(&qat_dc_stats.throughput_comp_bps.value.ui64, 1000UL * processed / time);
    }
}

static inline void 
updateThroughputDecomp(const uint64_t start, const uint64_t end) {
    const unsigned long ms = jiffies_to_msecs(end - start);
    const uint64_t time = atomic_add_64_nv(&decompressionTimeMs, ms);
    if (time > 0) {
	const uint64_t processed = qat_dc_stats.decomp_total_out_bytes.value.ui64;
	atomic_swap_64(&qat_dc_stats.throughput_decomp_bps.value.ui64, 1000UL * processed / time);
    }
}

int
qat_compress_init(void)
{

	Cpa16U numInstances = 0;

	qat_ksp = kstat_create("zfs", 0, "qat-dc", "misc",
	    KSTAT_TYPE_NAMED, sizeof (qat_dc_stats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (qat_ksp != NULL) 
	{
		qat_ksp->ks_data = &qat_dc_stats;
		kstat_install(qat_ksp);
	}

	if (CPA_STATUS_SUCCESS == cpaDcGetNumInstances(&numInstances) && numInstances > 0)
	{
	    printk(KERN_INFO LOG_PREFIX "started with %d DC instances\n", numInstances);
	}
	else
	{
	    printk(KERN_INFO LOG_PREFIX "initialized\n");
	}

	return 0;
}

void
qat_compress_fini(void)
{
	if (qat_ksp != NULL) 
	{
		kstat_delete(qat_ksp);
		qat_ksp = NULL;
	}
}

boolean_t
qat_use_accel(const qat_compress_dir_t dir, const size_t s_len)
{

    boolean_t ret = B_FALSE;

    switch (dir) 
    {
	case QAT_COMPRESS:
	    ret = (0 == zfs_qat_disable_compression) &&
		(QAT_MIN_BUF_SIZE <= s_len && s_len <= QAT_MAX_BUF_SIZE_COMP);
	    break;
	    
	case QAT_DECOMPRESS:
	    ret = (0 == zfs_qat_disable_decompression) &&
		(QAT_MIN_BUF_SIZE <= s_len && s_len <= QAT_MAX_BUF_SIZE_DECOMP);
	    break;
	    
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

	case CPA_DC_BAD_DATA:
	// The input data was not properly formed.
	QAT_STAT_BUMP(err_status_baddata);
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
register_op_status(const CpaStatus status) {

    switch (status) {

	case CPA_DC_OK:
	// No error detected by compression hardware. None.
	break;

	case CPA_DC_OVERFLOW:
	// Overflow detected. This is not an error, but an exception. Overflow is
	// supported and can be handled. 
	//
	// Resubmit with a larger output buffer.
	QAT_STAT_BUMP(err_op_overflow);
	break;

	case CPA_DC_EP_HARDWARE_ERR:
	// Request was not completed as an end point hardware error occurred (for
	// example, a parity error). 
	//
	// Discard output; resubmit affected request or abort session.
	QAT_STAT_BUMP(err_op_hw);
	break;

	case CPA_DC_SOFTERR:
	//  Other non-fatal detected. 
	//
	// Discard output; resubmit affected request or abort session.
	QAT_STAT_BUMP(err_op_sw);
	break;

	case CPA_DC_FATALERR:
	// Fatal error detected. 
	//
	// Discard output; restart or reset session.
	QAT_STAT_BUMP(err_op_fatal);
	break;

	case CPA_DC_INVALID_BLOCK_TYPE:
	//  Invalid block type (type = 3); invalid input stream detected for
	// decompression; for dynamic compression, corrupted intermediate data 
	//
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_BAD_STORED_BLOCK_LEN:
	//  Stored block length did not match one's complement; invalid input stream detected 
	//
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_TOO_MANY_CODES:
	// Too many length or distance codes; invalid input stream detected; for
	// dynamic compression, corrupted intermediate data 
	//
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_INCOMPLETE_CODE_LENS:
	//  Code length codes incomplete; invalid input stream detected; for dynamic
	// compression, corrupted intermediate data 
	//
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_REPEATED_LENS:
	//  Repeated lengths with no first length; invalid input stream detected; for
	// dynamic compression, corrupted intermediate data 
	//
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_MORE_REPEAT:
	//  Repeat more than specified lengths; invalid input stream detected; for
	// dynamic compression, corrupted intermediate data 
	//
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_BAD_LITLEN_CODES:
	// Invalid literal/length code lengths; invalid input stream detected; for
	// dynamic compression, corrupted intermediate data 
	//
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_BAD_DIST_CODES:
	//  Invalid distance code lengths; invalid input stream detected; for dynamic
	// compression, corrupted intermediate data 
	// 
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_INVALID_CODE:
	// Invalid literal/length or distance code in fixed or dynamic block; invalid input
	// stream detected; for dynamic compression, corrupted intermediate data 
	//
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_INVALID_DIST:
	// Distance is too far back in fixed or dynamic block; invalid input stream
	// detected; for dynamic compression, corrupted intermediate data 
	//
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_MAX_RESUBITERR:
	// On an error being detected, the firmware attempted to correct and
	// resubmitted the request, however, the maximum resubmit value was
	// exceeded. 
	//
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_INCOMPLETE_FILE_ERR:
	// The input file is incomplete. Note this is an indication that the request was
	// submitted with a CPA_DC_FLUSH_FINAL, however, a
	// BFINAL bit was not found in the request. 
	//
	// Continue with the session, if the file is not completed.
	// Restart or reset the session if the following request is
	// not related with the previous one.

	case CPA_DC_WDOG_TIMER_ERR:
	//  The request was not completed as a watchdog timer hardware event
	// occurred. 
	//
	//Discard output; resubmit affected request or abort session.

	case CPA_DC_VERIFY_ERROR:
	// CnV (formerly known as MCA) decompress check error detected. 
	//
	// Discard output; resubmit affected request or abort session.

	case CPA_DC_EMPTY_DYM_BLK:
	// Decompression request contained an empty dynamic stored block (not
	// supported). 
	//
	// In a stateless session abort the session. In a stateful
	// session decode the empty dynamic store block and continue.

	// TODO: add more constants if any

	default:
	QAT_STAT_BUMP(err_op_unknown);
	break;
    }
}

static void
qat_dc_callback_interrupt(CpaDcDpOpData *pOpData)
{
    if (pOpData->pCallbackTag != NULL) {
        complete((struct completion *)pOpData->pCallbackTag);
    }
}

static void
qat_dc_callback_polled(CpaDcDpOpData *pOpData)
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
	status = cpaDcInstanceGetInfo2(dcInstHandle, instanceInfo);
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
	status = cpaDcInstanceGetInfo2(dcInstHandle, instanceInfo);
	if (CPA_STATUS_SUCCESS == status) 
	{
	    strncpy(instName, instanceInfo->instName, CPA_INST_NAME_SIZE);
	}
    }

    VIRT_FREE(instanceInfo);

    return status;
}

static CpaStatus
waitForCompletion(const CpaInstanceHandle dcInstHandle, const CpaDcDpOpData *pOpData, const boolean_t polled, const unsigned long timeoutMs) 
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

    	    status = icp_sal_DcPollDpInstance(dcInstHandle, 1);
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

    status = cpaDcGetNumInstances(&num_inst);
    if (status != CPA_STATUS_SUCCESS || num_inst == 0) 
    {
            printk(KERN_ALERT LOG_PREFIX "failed counting instances, num_inst=%d, num_failed=%d (status=%d)\n",
                    num_inst, atomic_read(&numInitFailed), status);
            goto done;
    }

    status = PHYS_CONTIG_ALLOC(&handles, num_inst * sizeof(CpaInstanceHandle));
    if (status != CPA_STATUS_SUCCESS) 
    {
            printk(KERN_CRIT LOG_PREFIX "failed allocate space for instances, num_inst=%d (status=%d)\n", num_inst, status);
            goto done;
    }

    status = cpaDcGetInstances(num_inst, handles);
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

    PHYS_CONTIG_FREE(handles);

    return status;

}

/*
 * This function performs a decompression operation.
 */
static qat_compress_status_t
compPerformOp(const CpaInstanceHandle dcInstHandle, const CpaDcSessionHandle sessionHdl, 
    boolean_t polled,
    const char* src, const int src_len, 
    char* dest, const int dest_len, size_t *c_len)
{

    qat_compress_status_t ret = QAT_COMPRESS_FAIL;

    struct completion complete = {0};
    unsigned long timeout = 0;

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaFlatBuffer srcBuf = {0};
    CpaFlatBuffer destBuf = {0};

    // recovery from errors is more expensive then successful compression
    // therefore set the size of output buffer by Intel's recomendation
    // Destination buffer size in bytes = ceil(9 * Total input bytes / 8) + 55 bytes
    Cpa32U bufferSize = ceil( 9 * src_len, 8 ) + 55;

    CpaDcDpOpData *pOpData = NULL;

    CpaFlatBuffer headerBuf = {0};
    CpaFlatBuffer footerBuf = {0};
    Cpa32U hdr_sz = 0;
    Cpa32U foot_sz = 0;
    Cpa32U compressed_sz = 0;

    // printk(KERN_ALERT LOG_PREFIX "just inform, compress %d to %d bytes\n", src_len, dest_len);

    QAT_STAT_BUMP(comp_requests);
    QAT_STAT_INCR(comp_total_in_bytes, src_len);

    // source buffer
    if (CPA_STATUS_SUCCESS == status) 
    {
	status = PHYS_CONTIG_ALLOC_ALIGNED(&srcBuf.pData, src_len, 8);
	srcBuf.dataLenInBytes = src_len;
    }

    // destination buffer
    if (CPA_STATUS_SUCCESS == status) 
    {
	memcpy(srcBuf.pData, src, src_len);

	status = PHYS_CONTIG_ALLOC_ALIGNED(&destBuf.pData, bufferSize, 8);
	destBuf.dataLenInBytes = bufferSize;
    }

    // header buffer
    if (CPA_STATUS_SUCCESS == status) 
    {
        status = PHYS_CONTIG_ALLOC(&headerBuf.pData, ZLIB_HEAD_SZ);
	headerBuf.dataLenInBytes = ZLIB_HEAD_SZ;
    }
    
    // generate header
    if (CPA_STATUS_SUCCESS == status) 
    {
	// generate header into own buffer
	status = cpaDcGenerateHeader(sessionHdl, &headerBuf, &hdr_sz);
	if (CPA_STATUS_SUCCESS != status) 
	{
		QAT_STAT_BUMP(err_gen_header);
		printk(KERN_CRIT LOG_PREFIX "failed to generate header into buffer of size %d (status=%d)\n", 
		    headerBuf.dataLenInBytes, status);
	}
    }
    
    // allocate pOpData
    if (CPA_STATUS_SUCCESS == status) 
    {

        /* Allocate memory for operational data. Note this needs to be
         * 8-byte aligned, contiguous, resident in DMA-accessible
         * memory.
         */
        status = PHYS_CONTIG_ALLOC_ALIGNED(&pOpData, sizeof(CpaDcDpOpData), 8);
    }

    // submit operation
    if (CPA_STATUS_SUCCESS == status)
    {
        memset(pOpData, 0, sizeof(CpaDcDpOpData));

        pOpData->bufferLenToCompress = src_len;
        pOpData->bufferLenForData = bufferSize;
        pOpData->dcInstance = dcInstHandle;
        pOpData->pSessionHandle = sessionHdl;
        pOpData->srcBuffer = virt_to_phys(srcBuf.pData);
        pOpData->srcBufferLen = srcBuf.dataLenInBytes;
        pOpData->destBuffer = virt_to_phys(destBuf.pData);
        pOpData->destBufferLen = destBuf.dataLenInBytes;
        pOpData->sessDirection = CPA_DC_DIR_COMPRESS;
        INIT_DC_DP_CNV_OPDATA(pOpData);
        pOpData->thisPhys = virt_to_phys(pOpData);

	if (polled)
	{
	    pOpData->pCallbackTag = (void *)0;
	} 
	else
	{
	    init_completion(&complete);
    	    pOpData->pCallbackTag = (void *)&complete;
    	}

        /** Enqueue and submit operation */
        status = cpaDcDpEnqueueOp(pOpData, CPA_TRUE);
        if (CPA_STATUS_SUCCESS != status)
        {
	    register_error_status(status);
            printk(KERN_CRIT LOG_PREFIX "compression job submit failed (status = %d)\n", status);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {

	// wait for bigger packets longer but at least 0.5 sec
        timeout = getTimeoutMs(dest_len, QAT_MAX_BUF_SIZE_COMP);

	status = waitForCompletion(dcInstHandle, pOpData, polled, timeout);
    }

    /*
     * We now check the results
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (pOpData->responseStatus != CPA_STATUS_SUCCESS)
        {

            register_op_status(pOpData->results.status);

	    // overflow is normal condition, don't interpret as failure
	    if (pOpData->results.status == CPA_DC_OVERFLOW) {
                // printk(KERN_ERR LOG_PREFIX "status=%d and results status is overflow (op_status = %d), probably should set UNCOMPRESSIBLE here\n",
                //          pOpData->results.status);
                ret = QAT_COMPRESS_UNCOMPRESSIBLE;
	    
	    } else {
		
		register_error_status(pOpData->responseStatus);
        	printk(KERN_ERR LOG_PREFIX "compression of %d to %d failed (status = %d)\n",
            	    src_len, dest_len, pOpData->responseStatus);
	    
	    }

            status = CPA_STATUS_FAIL;
        }
        else
        {
            if (pOpData->results.status != CPA_DC_OK)
            {
		register_op_status(pOpData->results.status);
                printk(KERN_ERR LOG_PREFIX "compression results status not as expected (op_status = %d)\n",
                          pOpData->results.status);
                status = CPA_STATUS_FAIL;
            }
            else
            {
                // PRINT_DBG("Data consumed %d\n", pOpData->results.consumed);
                // PRINT_DBG("Data produced %d\n", pOpData->results.produced);
                // PRINT_DBG("CRC checksum 0x%x\n", pOpData->results.checksum);
		
		// if result is already bigger then buffer+header, no need to generate footer
		if (pOpData->results.produced + hdr_sz > dest_len) 
		{
            		QAT_STAT_BUMP(err_overflow);
            		printk(KERN_DEBUG LOG_PREFIX "compression of %d produced output of %d (+%d header) bytes but output buffer is only %d\n", 
				src_len, pOpData->results.produced, hdr_sz, dest_len);

			ret = QAT_COMPRESS_UNCOMPRESSIBLE;
            		status = CPA_STATUS_FAIL;
        	} 
        	else 
        	{
			// save result size
            		// copy data from output buffer to result later
			compressed_sz = pOpData->results.produced;
        	}
            }
        }
    }

    // allocate buffer for footer
    if (CPA_STATUS_SUCCESS == status) 
    {
	status = PHYS_CONTIG_ALLOC(&footerBuf.pData, ZLIB_FOOT_SZ);
        footerBuf.dataLenInBytes = ZLIB_FOOT_SZ;
    }

    // generate footer
    if (CPA_STATUS_SUCCESS == status) 
    {
        // generate footer into own buffer but updates pOpData->results
        status = cpaDcGenerateFooter(sessionHdl, &footerBuf, &pOpData->results);
	if (CPA_STATUS_SUCCESS != status) 
	{
		QAT_STAT_BUMP(err_gen_footer);
		printk(KERN_CRIT LOG_PREFIX "failed to generate footer into buffer of size %d (status=%d)\n", 
		    footerBuf.dataLenInBytes, status);
	}
    }

    // store results into destination
    if (CPA_STATUS_SUCCESS == status) 
    {
	// compressed data + footer
	foot_sz = pOpData->results.produced - compressed_sz;

	if (hdr_sz + compressed_sz + foot_sz > dest_len) {

	    QAT_STAT_BUMP(err_overflow);
            printk(KERN_DEBUG LOG_PREFIX "compression of %d produced output of %d (+%d header, +%d footer) bytes but output buffer is only %d\n", 
			src_len, compressed_sz, hdr_sz, foot_sz, dest_len);

	    ret = QAT_COMPRESS_UNCOMPRESSIBLE;
	    status = CPA_STATUS_FAIL;

	} else {

	    // copy compression result to destination
	    memcpy(&dest[0], 	  			headerBuf.pData, 	hdr_sz);
	    memcpy(&dest[hdr_sz], 			destBuf.pData, 		compressed_sz);
	    memcpy(&dest[hdr_sz + compressed_sz],       footerBuf.pData,        foot_sz);

	    // save size of compressed data
	    *c_len = hdr_sz + compressed_sz + foot_sz;

	    QAT_STAT_INCR(comp_total_out_bytes, *c_len);

	    ret = QAT_COMPRESS_SUCCESS;
	}
    }

    if (CPA_STATUS_SUCCESS != status) {
	QAT_STAT_BUMP(comp_fails);
    }

    /*
     * Free the memory!
     */
    PHYS_CONTIG_FREE(pOpData);
    PHYS_CONTIG_FREE(srcBuf.pData);
    PHYS_CONTIG_FREE(destBuf.pData);
    PHYS_CONTIG_FREE(headerBuf.pData);
    PHYS_CONTIG_FREE(footerBuf.pData);

    return ret;

}

/*
 * This function performs a decompression operation.
 */
static qat_compress_status_t
decompPerformOp(const CpaInstanceHandle dcInstHandle, const CpaDcSessionHandle sessionHdl, 
    const boolean_t polled,
    const char* src, const int src_len, 
    char* dest, const int dest_len, size_t *c_len)
{

    qat_compress_status_t ret = QAT_COMPRESS_FAIL;

    struct completion complete = {0};
    unsigned long timeout = 0;

    CpaStatus status = CPA_STATUS_SUCCESS;
    // For decompression operations, the minimal destination buffer size should be 258 bytes.
    const Cpa32U bufferSize = max(258L, (long)dest_len);
    CpaFlatBuffer srcBuf = {0};
    CpaFlatBuffer destBuf = {0};
    CpaDcDpOpData *pOpData = NULL;

    // printk(KERN_ALERT LOG_PREFIX "just inform, decompress %d to %d bytes\n", src_len, dest_len);

    QAT_STAT_BUMP(decomp_requests);
    QAT_STAT_INCR(decomp_total_in_bytes, src_len);

    // allocate source buffer
    if (CPA_STATUS_SUCCESS == status) 
    {
	status = PHYS_CONTIG_ALLOC_ALIGNED(&srcBuf.pData, src_len - ZLIB_HEAD_SZ, 8);
	srcBuf.dataLenInBytes = src_len - ZLIB_HEAD_SZ;
    }
    
    // allocate destination buffer
    if (CPA_STATUS_SUCCESS == status) 
    {
	memcpy(srcBuf.pData, &src[ZLIB_HEAD_SZ], src_len - ZLIB_HEAD_SZ);

	status = PHYS_CONTIG_ALLOC_ALIGNED(&destBuf.pData, bufferSize, 8);
	destBuf.dataLenInBytes = bufferSize;
    }
    
    // allocate pOpData
    if (CPA_STATUS_SUCCESS == status) 
    {

        /* Allocate memory for operational data. Note this needs to be
         * 8-byte aligned, contiguous, resident in DMA-accessible
         * memory.
         */
        status = PHYS_CONTIG_ALLOC_ALIGNED(&pOpData, sizeof(CpaDcDpOpData), 8);
    }

    // perform operation
    if (CPA_STATUS_SUCCESS == status)
    {
        memset(pOpData, 0, sizeof(CpaDcDpOpData));

        pOpData->bufferLenToCompress = src_len - ZLIB_HEAD_SZ;
        pOpData->bufferLenForData = bufferSize;
        pOpData->dcInstance = dcInstHandle;
        pOpData->pSessionHandle = sessionHdl;
        pOpData->srcBuffer = virt_to_phys(srcBuf.pData);
        pOpData->srcBufferLen = srcBuf.dataLenInBytes;
        pOpData->destBuffer = virt_to_phys(destBuf.pData);
        pOpData->destBufferLen = destBuf.dataLenInBytes;
        pOpData->sessDirection = CPA_DC_DIR_DECOMPRESS;
        INIT_DC_DP_CNV_OPDATA(pOpData);
        pOpData->thisPhys = virt_to_phys(pOpData);

	if (polled) 
	{
	    pOpData->pCallbackTag = (void *)0;
	} 
	else 
	{
	    init_completion(&complete);
    	    pOpData->pCallbackTag = (void *)&complete;
        }

        /** Enqueue and submit operation */
        status = cpaDcDpEnqueueOp(pOpData, CPA_TRUE);
        if (CPA_STATUS_SUCCESS != status)
        {
    	    register_error_status(status);
            printk(KERN_CRIT LOG_PREFIX "decompression job submit failed (status = %d)\n", status);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
	// wait for bigger packets longer but at lease 0.5 sec
        timeout = getTimeoutMs(dest_len, QAT_MAX_BUF_SIZE_DECOMP);

	status = waitForCompletion(dcInstHandle, pOpData, polled, timeout);
    }

    /*
     * We now check the results
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (pOpData->responseStatus != CPA_STATUS_SUCCESS)
        {
	    register_error_status(pOpData->responseStatus);
	    register_op_status(pOpData->results.status);
	
            printk(KERN_ERR LOG_PREFIX "decompression operation failed with op_status=%d (status = %d)\n",
                pOpData->results.status, pOpData->responseStatus);

            status = CPA_STATUS_FAIL;
        }
        else
        {
            if (pOpData->results.status != CPA_DC_OK)
            {
		register_op_status(pOpData->results.status);
                printk(KERN_ERR LOG_PREFIX "decompression results status not as expected (op_status = %d)\n",
                          pOpData->results.status);
                status = CPA_STATUS_FAIL;
            }
            else
            {
                // PRINT_DBG("Data consumed %d\n", pOpData->results.consumed);
                // PRINT_DBG("Data produced %d\n", pOpData->results.produced);
                // PRINT_DBG("CRC checksum 0x%x\n", pOpData->results.checksum);
		
		if (pOpData->results.produced > dest_len) {
            		QAT_STAT_BUMP(err_overflow);
            		printk(KERN_ERR LOG_PREFIX "decompression of %d produced output of %d bytes but output buffer is only %d\n", 
				src_len, pOpData->results.produced, dest_len);
            		status = CPA_STATUS_FAIL;

        	} else {

            		// copy data from output buffer to destination
            		memcpy(dest, destBuf.pData, pOpData->results.produced);

			// save result size
            		*c_len = pOpData->results.produced;
            		
            		QAT_STAT_INCR(decomp_total_out_bytes, *c_len);

            		ret = QAT_COMPRESS_SUCCESS;
        	}
            }
        }
    }

    if (CPA_STATUS_SUCCESS != status) {
	QAT_STAT_BUMP(decomp_fails);
    }

    /*
     * Free the memory!
     */
    PHYS_CONTIG_FREE(pOpData);
    PHYS_CONTIG_FREE(srcBuf.pData);
    PHYS_CONTIG_FREE(destBuf.pData);

    return ret;
}

/*************************************************************************
*
* convert GZIP compression level to QAT DC
*
*************************************************************************/
static inline CpaDcCompLvl 
compLevel(const int level) 
{

    switch (level) 
    {
	case 1: return CPA_DC_L1;
	case 2: return CPA_DC_L2;
	case 3: return CPA_DC_L3;
	case 4: return CPA_DC_L4;
	case 5: return CPA_DC_L5;
	case 6: return CPA_DC_L6;
	case 7: return CPA_DC_L7;
	case 8: return CPA_DC_L8;
	case 9: return CPA_DC_L9;
    }

    // above level 4 no significant compression ratio increase observed
    return CPA_DC_L4;
}


/*************************************************************************
*
* QAT Compression/Decompression action
*
*************************************************************************/
static qat_compress_status_t 
qat_action( qat_compress_status_t (*func)(const CpaInstanceHandle, const CpaDcSessionHandle, const boolean_t, const char*, const int, char*, const int, size_t*),
    const int level, const char* src, const int src_len, char* dest, const int dest_len, size_t *c_len)
{

    qat_compress_status_t ret = QAT_COMPRESS_FAIL;

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaDcInstanceCapabilities cap = {0};
    Cpa32U sess_size = 0;
    Cpa32U ctx_size = 0;
    CpaDcSessionHandle sessionHdl = NULL;
    CpaInstanceHandle dcInstHandle = NULL;
    CpaDcSessionSetupData sd = {0};
    /* Variables required to setup the intermediate buffer */
    CpaBufferList *bufferInterArray = NULL;
    Cpa16U numInterBuffLists = 0;
    Cpa16U bufferNum = 0;
    Cpa16U numInterBufs = 0;
    Cpa32U buffMetaSize = 0;
    Cpa32U bufSize = dest_len;
    boolean_t polled = B_FALSE;

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a data compression service.
     * Note this is the same as was done for "traditional" api.
     */
    status = getInstance(&dcInstHandle);
    if (status != CPA_STATUS_SUCCESS || dcInstHandle == NULL)
    {
	goto failed;
    }

    /* Query Capabilities */
    status = cpaDcQueryCapabilities(dcInstHandle, &cap);
    if (status != CPA_STATUS_SUCCESS)
    {
	printk(KERN_CRIT LOG_PREFIX "failed to get instance capabilities (status=%d)\n", status);
        goto failed;
    }

    if (!cap.statelessDeflateDecompression || 
	!cap.statelessDeflateCompression ||
	!cap.checksumAdler32 ||
        !cap.dynamicHuffman)
    {
	printk(KERN_CRIT LOG_PREFIX "unsupported functionality\n");
        goto failed;
    }

    // drop counter after successfull init
    atomic_set(&numInitFailed, 0);

    if (cap.dynamicHuffmanBufferReq)
    {
        status = cpaDcBufferListGetMetaSize(dcInstHandle, 1, &buffMetaSize);

        if (CPA_STATUS_SUCCESS == status)
        {
            status = cpaDcGetNumIntermediateBuffers(dcInstHandle, &numInterBuffLists);
        }
        if (CPA_STATUS_SUCCESS == status && 0 != numInterBuffLists)
        {
            status = PHYS_CONTIG_ALLOC(&bufferInterArray, numInterBuffLists * sizeof(CpaBufferList));
        }
        for (bufferNum = 0; bufferNum < numInterBuffLists; bufferNum++)
        {
            if (CPA_STATUS_SUCCESS == status)
            {
                status = PHYS_CONTIG_ALLOC(&bufferInterArray[bufferNum].pPrivateMetaData, buffMetaSize);
            }

            if (CPA_STATUS_SUCCESS == status)
            {
                status = PHYS_CONTIG_ALLOC(&bufferInterArray[bufferNum].pBuffers, sizeof(CpaFlatBuffer));
            }

            if (CPA_STATUS_SUCCESS == status)
            {
                /* Implementation requires an intermediate buffer approximately
                           twice the size of the output buffer */
                status = PHYS_CONTIG_ALLOC(&bufferInterArray[bufferNum].pBuffers->pData, 2 * bufSize);
                bufferInterArray[bufferNum].numBuffers = 1;
                bufferInterArray[bufferNum].pBuffers->dataLenInBytes = 2 * bufSize;
            }

        } /* End numInterBuffLists */

	if (CPA_STATUS_SUCCESS != status) {
	    printk(KERN_ALERT LOG_PREFIX "failed allocating %d interBuffers of size %d\n", numInterBuffLists, 2 * bufSize);
	}
    }

    /*
     * Set the address translation function for the instance
     */
    if (CPA_STATUS_SUCCESS == status) 
    {
        status = cpaDcSetAddressTranslation(dcInstHandle, (void *)virt_to_phys);
    }

    /* Start DataCompression component */
    if (CPA_STATUS_SUCCESS == status) 
    {
        status = cpaDcStartInstance(dcInstHandle, numInterBufs, &bufferInterArray);
	if (CPA_STATUS_SUCCESS != status) 
	{
	    printk(KERN_CRIT LOG_PREFIX "failed to start instance with %d buffers of %d (status=%d)\n", 
		numInterBufs, 2 * bufSize, status);
	}
    }

    if (CPA_STATUS_SUCCESS == status) {
	status = isInstancePolled(dcInstHandle, &polled);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Register callback function for the instance */
	if (polled)
	{
	    status = cpaDcDpRegCbFunc(dcInstHandle, qat_dc_callback_polled);
	}
	else
	{
	    status = cpaDcDpRegCbFunc(dcInstHandle, qat_dc_callback_interrupt);
	}
    }

    /*
     * We now populate the fields of the session operational data and create
     * the session.  Note that the size required to store a session is
     * implementation-dependent, so we query the API first to determine how
     * much memory to allocate, and then allocate that memory.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
	// ignored by decompression
        sd.compLevel = compLevel(level);
        sd.compType = CPA_DC_DEFLATE;
        sd.huffType = CPA_DC_HT_FULL_DYNAMIC;
        /* If the implementation supports it, the session will be configured
         * to select static Huffman encoding over dynamic Huffman as
         * the static encoding will provide better compressibility.
         */
        if (cap.autoSelectBestHuffmanTree)
        {
            sd.autoSelectBestHuffmanTree = CPA_TRUE;
        }
	else
        {
            sd.autoSelectBestHuffmanTree = CPA_FALSE;
        }
        sd.sessDirection = CPA_DC_DIR_COMBINED;
        sd.sessState = CPA_DC_STATELESS;
#if (CPA_DC_API_VERSION_NUM_MAJOR == 1 && CPA_DC_API_VERSION_NUM_MINOR < 6)
        sd.deflateWindowSize = 7;
#endif
        sd.checksum = CPA_DC_ADLER32;

        /* Determine size of session context to allocate */
        status = cpaDcGetSessionSize(dcInstHandle, &sd, &sess_size, &ctx_size);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate session memory */
        status = PHYS_CONTIG_ALLOC(&sessionHdl, sess_size);
    }

    /* Initialize the Stateless session */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaDcDpInitSession(dcInstHandle,
                                    sessionHdl, /* session memory */
                                    &sd);       /* session setup data */
        if (CPA_STATUS_SUCCESS != status) 
        {
    	    printk(KERN_CRIT LOG_PREFIX "failed to init session (status=%d)\n", status);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

        /* Perform Compression operation */
        ret = (*func)(dcInstHandle, sessionHdl, polled, src, src_len, dest, dest_len, c_len);
	
        sessionStatus = cpaDcDpRemoveSession(dcInstHandle, sessionHdl);

        /* Maintain status of remove session only when status of all operations
         * before it are successful. */
        if (CPA_STATUS_SUCCESS == status)
        {
            status = sessionStatus;
        }
    }

    /*
     * Free up memory, stop the instance, etc.
     */

    /* Free session Context */
    PHYS_CONTIG_FREE(sessionHdl);

    cpaDcStopInstance(dcInstHandle);

    /* Free intermediate buffers */
    if (bufferInterArray != NULL)
    {
        for (bufferNum = 0; bufferNum < numInterBuffLists; bufferNum++)
        {
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum].pBuffers->pData);
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum].pBuffers);
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum].pPrivateMetaData);
        }
        PHYS_CONTIG_FREE(bufferInterArray);
    }

    return ret;

// go here before any initializations
failed:

    QAT_STAT_BUMP(init_failed);
    int failed = atomic_inc_return(&numInitFailed);

    if (zfs_qat_init_failure_threshold > 0 && failed >= zfs_qat_init_failure_threshold) 
    {
	printk(KERN_ALERT LOG_PREFIX "disabled because number of failed initializations %d is equal or greater then threshold %d\n",
                    failed, zfs_qat_init_failure_threshold);

        zfs_qat_disable_compression = 1;
        zfs_qat_disable_decompression = 1;
    }

    return ret;
}

/*************************************************************************
*
* QAT Compression/Decompression entry point
*
*************************************************************************/
qat_compress_status_t
qat_compress(const qat_compress_dir_t dir, const int level, const char *src, const int src_len, char *dest, const int dest_len, size_t *c_len) 
{

    qat_compress_status_t ret = QAT_COMPRESS_FAIL;

    const unsigned long start = jiffies;

    switch (dir) 
    {

        case QAT_COMPRESS:
	    // printk(KERN_ALERT LOG_PREFIX "just info, requested to compress %d bytes to buffer size %d\n", src_len, dest_len);
            ret = qat_action(compPerformOp, level, src, src_len, dest, dest_len, c_len);
	    if (QAT_COMPRESS_SUCCESS == ret) 
	    {
		updateThroughputComp(start, jiffies);
	    }
            break;

        case QAT_DECOMPRESS:
	    // printk(KERN_ALERT LOG_PREFIX "just info, requested to decompress %d bytes to buffer size %d\n", src_len, dest_len);
            ret = qat_action(decompPerformOp, level, src, src_len, dest, dest_len, c_len);
	    if (QAT_COMPRESS_SUCCESS == ret) 
	    {
		updateThroughputDecomp(start, jiffies);
	    }
            break;
        
        default:
            // not possible
            break;
    }

    return ret;
}


module_param(zfs_qat_disable_compression, int, 0644);
MODULE_PARM_DESC(zfs_qat_disable_compression, "Disable QAT compression");

module_param(zfs_qat_disable_decompression, int, 0644);
MODULE_PARM_DESC(zfs_qat_disable_decompression, "Disable QAT decompression");

// int zfs_qat_init_failure_threshold = 100;
// module_param(zfs_qat_init_failure_threshold, int, 0644);
// MODULE_PARM_DESC(zfs_qat_init_failure_threshold, "Threshold (number of init failures) to consider disabling QAT");

#endif
