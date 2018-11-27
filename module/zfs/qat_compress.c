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
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/rwlock.h>
#include <sys/zfs_context.h>

#include <cpa.h>
#include <dc/cpa_dc_dp.h>
#include <icp_sal_poll.h>

#include "qat_common.h"
#include "qat_compress.h"
#include "qat_cnv_utils.h"

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

/*
Depending on the specifics of the particular algorithm and QAT API parameters, a
relatively small decrease in performance may be observed for submission requests
around a buffer/packet size of 2kB to 4kB. This is expected due to optimizations in the
QAT software that can apply for requests of a certain size.
 */

#define	QAT_MIN_BUF_SIZE	(4*1024)
#define	QAT_MAX_BUF_SIZE	(128*1024)
#define	QAT_MAX_BUF_SIZE_COMP	QAT_MAX_BUF_SIZE
#define QAT_MAX_BUF_SIZE_DECOMP QAT_MAX_BUF_SIZE

#define LOG_PREFIX "ZFS-QAT/dc: "

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
	 * Number of jobs submitted to qat compression engine.
	 */
	kstat_named_t comp_requests;
	/*
	 * Total bytes sent to qat compression engine.
	 */
	kstat_named_t comp_total_in_bytes;
	/* number of bytes successfully compressed */
	kstat_named_t comp_total_success_bytes;
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
	/* compression throughput in bytes-per-second */
	kstat_named_t comp_throughput_bps;
	kstat_named_t comp_requests_per_second;
	/*
	 * Number of jobs submitted to qat de-compression engine.
	 */
	kstat_named_t decomp_requests;
	/*
	 * Total bytes sent to qat de-compression engine.
	 */
	kstat_named_t decomp_total_in_bytes;
	/* number of bytes successfully decompressed */
	kstat_named_t decomp_total_success_bytes;
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
	/* decompression throughput in bytes-per-second */
	kstat_named_t decomp_throughput_bps;
	kstat_named_t decomp_requests_per_second;

	/* number of times no available instance found (all are busy)
	   if you see this number high, increase amount of instances in
	   qat config file, [KERNEL_QAT] section
	 */
	kstat_named_t err_no_instance_available;
	/* number of times memory can't be allocated */
	kstat_named_t err_out_of_mem;
	/* number of times engine failed to perform the operation in time */
	kstat_named_t err_timeout;
	/* number of times engine failed to generate ZLIB header */
	kstat_named_t err_gen_header;
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

} qat_stats_t;

qat_stats_t qat_dc_stats = {
		{ "init_failed",			KSTAT_DATA_UINT64 },

		{ "comp_requests",			KSTAT_DATA_UINT64 },
		{ "comp_total_in_bytes",		KSTAT_DATA_UINT64 },
		{ "comp_total_success_bytes",		KSTAT_DATA_UINT64 },
		{ "comp_total_out_bytes",		KSTAT_DATA_UINT64 },
		{ "comp_fails",				KSTAT_DATA_UINT64 },
		{ "comp_throughput_bps",		KSTAT_DATA_UINT64 },
		{ "comp_requests_per_second",		KSTAT_DATA_UINT64 },

		{ "decomp_requests",			KSTAT_DATA_UINT64 },
		{ "decomp_total_in_bytes",		KSTAT_DATA_UINT64 },
		{ "decomp_total_success_bytes",		KSTAT_DATA_UINT64 },
		{ "decomp_total_out_bytes",		KSTAT_DATA_UINT64 },
		{ "decomp_fails",			KSTAT_DATA_UINT64 },
		{ "decomp_throughput_bps",		KSTAT_DATA_UINT64 },
		{ "decomp_requests_per_second",		KSTAT_DATA_UINT64 },

		{ "err_no_instance_available",          KSTAT_DATA_UINT64 },
		{ "err_out_of_mem",			KSTAT_DATA_UINT64 },
		{ "err_timeout",                        KSTAT_DATA_UINT64 },
		{ "err_gen_header",                     KSTAT_DATA_UINT64 },
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
};

typedef struct qat_instance_info
{
	CpaInstanceHandle dcInstHandle;
	CpaBoolean instanceStarted;
	CpaBoolean instanceReady;
	CpaBoolean polled;
	CpaBoolean capable;
	CpaBoolean autoSelectBestHuffmanTree;

	Cpa16U numInterBuffLists;
	CpaBufferList **bufferInterArray;

	CpaFlatBuffer headerBuf __attribute__ ((aligned(8)));
	CpaFlatBuffer footerBuf __attribute__ ((aligned(8)));

	Cpa8U headerData[ZLIB_HEAD_SZ] __attribute__ ((aligned(8)));
	Cpa8U footerData[ZLIB_FOOT_SZ] __attribute__ ((aligned(8)));

	int instNum;

} qat_instance_info_t;

/* 128 is a maximum number of DC instances on one QAT controller */
#define MAX_INSTANCES 128

/* module parameters */
int zfs_qat_disable_dc_benchmark = 0;
int zfs_qat_disable_compression = 0;
int zfs_qat_disable_decompression = 0;

static qat_instance_info_t *instances = NULL;

static kstat_t *qat_ksp = NULL;
static struct kmem_cache *opCache = NULL;
static struct kmem_cache *bufferCache = NULL;
static struct kmem_cache *flatbufferCache = NULL;
static struct kmem_cache *interBufferCache = NULL;
static struct kmem_cache *bufferListCache = NULL;

/* dynamic cache, sessions */
static struct kmem_cache *sessionCache = NULL;
/* dynamic cache, metadata-cache: buffMetaSize */
static struct kmem_cache *metadataCache = NULL;
/* dynamic cache N x sizeof(CpaBufferList*) */
static struct kmem_cache *bufferListPtrCache = NULL;

static atomic_t numInitFailed = ATOMIC_INIT(0);
static atomic_t initialized = ATOMIC_INIT(0);
static atomic_t instance_lock[MAX_INSTANCES] = { ATOMIC_INIT(0) };
static atomic_t current_instance_number = ATOMIC_INIT(-1);

// static atomic_long_t lastCompThUpdate = ATOMIC_LONG_INIT(0);
// static atomic_long_t lastDecompThUpdate = ATOMIC_LONG_INIT(0);

static spinlock_t next_instance_lock;
static spinlock_t compression_time_lock;
static spinlock_t decompression_time_lock;
// static rwlock_t instance_storage_lock;
static rwlock_t session_cache_lock;
static rwlock_t metadata_cache_lock;
static rwlock_t bufferlistptr_cache_lock;

static atomic_long_t noInstanceMessageShown = ATOMIC_LONG_INIT(0);
static atomic_long_t getInstanceMessageShown = ATOMIC_LONG_INIT(0);
static atomic_long_t getInstanceFailed = ATOMIC_LONG_INIT(0);

static volatile struct timespec compressionTime = {0};
static volatile struct timespec decompressionTime = {0};

static struct timespec engineStarted = {0};

#define	QAT_STAT_INCR(stat, val) \
		atomic_add_64(&qat_dc_stats.stat.value.ui64, (val));
#define	QAT_STAT_BUMP(stat) \
		atomic_inc_64(&qat_dc_stats.stat.value.ui64);

static void
qat_dc_callback_interrupt(CpaDcDpOpData *pOpData)
{
	if (likely(pOpData->pCallbackTag != NULL))
	{
		complete((struct completion *)pOpData->pCallbackTag);
	}
}

static void
qat_dc_callback_polled(CpaDcDpOpData *pOpData)
{
	pOpData->pCallbackTag = (void *)1;
}

#if 0
static CpaStatus
requiresPhysicallyContiguousMemory(const CpaInstanceHandle dcInstHandle, CpaBoolean *contig)
{
	CpaStatus status;
	CpaInstanceInfo2 *instanceInfo = NULL;

	status = VIRT_ALLOC(&instanceInfo,sizeof(CpaInstanceInfo2));

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		status = cpaDcInstanceGetInfo2(dcInstHandle, instanceInfo);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		*contig = instanceInfo->requiresPhysicallyContiguousMemory;
	}

	VIRT_FREE(instanceInfo);

	return status;
}
#endif

static CpaStatus
isInstancePolled(const CpaInstanceHandle dcInstHandle, CpaBoolean *polled)
{
	CpaStatus status;
	CpaInstanceInfo2 *instanceInfo = NULL;

	status = VIRT_ALLOC(&instanceInfo,sizeof(CpaInstanceInfo2));

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		// get type of instance, polled (1) or interrupt (0)
		status = cpaDcInstanceGetInfo2(dcInstHandle, instanceInfo);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		*polled = instanceInfo->isPolled;
	}

	VIRT_FREE(instanceInfo);

	return status;
}



static inline int
getNextInstance(const Cpa16U num_inst)
{
	int inst = 0;

	spin_lock(&next_instance_lock);
	inst = atomic_inc_return(&current_instance_number) % num_inst;
	spin_unlock(&next_instance_lock);

	return (inst);
}

static inline CpaBoolean
check_and_lock(const Cpa16U instanceNr)
{
	CpaBoolean ret = CPA_FALSE;

	// write_lock(&instance_storage_lock);
	smp_mb__before_atomic();
	if (likely(0 == atomic_read(&instance_lock[instanceNr]))) {
		atomic_inc(&instance_lock[instanceNr]);
		ret = CPA_TRUE;
	}
	// write_unlock(&instance_storage_lock);
	smp_mb__after_atomic();

	return (ret);
}

static inline void
unlock_instance(const Cpa16U instanceNr)
{
	// write_lock(&instance_storage_lock);
	smp_mb__before_atomic();
	atomic_dec(&instance_lock[instanceNr]);
	smp_mb__after_atomic();
	// write_unlock(&instance_storage_lock);
}

static inline void
updateThroughputComp(const uint64_t start, const uint64_t end)
{
	struct timespec ts;
        struct timespec now;
        struct timespec diff;

        getnstimeofday(&now);
        diff = timespec_sub(now, engineStarted);

	jiffies_to_timespec(end - start, &ts);

	spin_lock(&compression_time_lock);

	compressionTime = timespec_add(compressionTime, ts);
	if (likely(compressionTime.tv_sec > 0))
	{
		const uint64_t processed = qat_dc_stats.comp_total_success_bytes.value.ui64;
		qat_dc_stats.comp_throughput_bps.value.ui64 =
			processed / compressionTime.tv_sec;
	}

	if (likely(diff.tv_sec > 0))
        {
                qat_dc_stats.comp_requests_per_second.value.ui64 =
                        qat_dc_stats.comp_requests.value.ui64 / diff.tv_sec;
        }

	spin_unlock(&compression_time_lock);
}

static inline void
updateThroughputDecomp(const uint64_t start, const uint64_t end)
{
	struct timespec ts;
        struct timespec now;
        struct timespec diff;

        getnstimeofday(&now);
        diff = timespec_sub(now, engineStarted);

	jiffies_to_timespec(end - start, &ts);

	spin_lock(&decompression_time_lock);

	decompressionTime = timespec_add(decompressionTime, ts);
	if (likely(decompressionTime.tv_sec > 0))
	{
		const uint64_t processed = qat_dc_stats.decomp_total_out_bytes.value.ui64;
		atomic_swap_64(&qat_dc_stats.decomp_throughput_bps.value.ui64, processed / decompressionTime.tv_sec);
	}

	if (likely(diff.tv_sec > 0))
        {
                atomic_swap_64(&qat_dc_stats.decomp_requests_per_second.value.ui64,
                        qat_dc_stats.decomp_requests.value.ui64 / diff.tv_sec);
        }
	spin_unlock(&decompression_time_lock);
}

/*******************************************************
 * CpaBufferList (static cache)
 *******************************************************/
static inline CpaStatus
CREATE_BUFFERLIST(CpaBufferList **ptr)
{
        CpaStatus status = CPA_STATUS_FAIL;

        /* set to NULL even if it fails to avoid dealocation issues later */
        *ptr = NULL;

        if (likely(NULL != bufferListCache))
        {
                void *result = kmem_cache_alloc(bufferListCache, GFP_KERNEL);
                if (likely(NULL != result))
                {
                        *ptr = (CpaBufferList*)result;
                        status = CPA_STATUS_SUCCESS;
                }
                else
                {
                        status = CPA_STATUS_RESOURCE;
                }
        }

        return status;
}

#define DESTROY_BUFFERLIST(ptr) _destroy_bufferlist(&(ptr))
static inline void
_destroy_bufferlist(CpaBufferList **ptr)
{
        if (likely(NULL != *ptr))
        {
                if (likely(NULL != bufferListCache))
                {
                        kmem_cache_free(bufferListCache, *ptr);
                }
                *ptr = NULL;
        }
}

/*******************************************************
 * CpaFlatBuffer (static cache)
 *******************************************************/
static inline CpaStatus
CREATE_FLATBUFFER(CpaFlatBuffer **ptr)
{
        CpaStatus status = CPA_STATUS_FAIL;

        /* set to NULL even if it fails to avoid dealocation issues later */
        *ptr = NULL;

        if (likely(NULL != flatbufferCache))
        {
                void *result = kmem_cache_alloc(flatbufferCache, GFP_KERNEL);
                if (likely(NULL != result))
                {
                        *ptr = (CpaFlatBuffer*)result;
                        status = CPA_STATUS_SUCCESS;
                }
                else
                {
                        status = CPA_STATUS_RESOURCE;
                }
        }

        return status;
}

#define DESTROY_FLATBUFFER(ptr) _destroy_flatbuffer(&(ptr))
static inline void
_destroy_flatbuffer(CpaFlatBuffer **ptr)
{
        if (likely(NULL != *ptr))
        {
                if (likely(NULL != flatbufferCache))
                {
                        kmem_cache_free(flatbufferCache, *ptr);
                }
                *ptr = NULL;
        }
}

/************************************
 * static kernel cache for input/output
 ************************************/
static inline CpaStatus
CREATE_BUFFER(Cpa8U **ptr)
{
	CpaStatus status = CPA_STATUS_FAIL;

	/* set to NULL even if it fails to avoid dealocation issues later */
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

	return (status);
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

/************************************
 * static kernel cache for opData
 ************************************/
static inline CpaStatus
CREATE_OPDATA(CpaDcDpOpData **ptr)
{
	CpaStatus status = CPA_STATUS_FAIL;

	/* set to NULL even if it fails to avoid dealocation issues later */
	*ptr = NULL;

	if (likely(NULL != opCache))
	{
		void *result = kmem_cache_alloc(opCache, GFP_KERNEL);
		if (likely(NULL != result))
		{
			*ptr = (CpaDcDpOpData*)result;
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
_destroy_opdata(CpaDcDpOpData **ptr)
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
 * dynamic kernel cache for sessions
 ************************************/
static inline CpaStatus
getReadySessionCache(Cpa16U size)
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

		sessionCache = kmem_cache_create("CpaDcSessions",
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

/* CpaCySymSessionCtx is already a pointer
 * so it will be translated to void **
 */
static inline CpaStatus
CREATE_SESSION(CpaDcSessionHandle *sessionCtx)
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
_destroy_session(CpaDcSessionHandle *sessionCtx)
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

/*******************************************************
 * Metadata buffers (dynamic cache)
 *******************************************************/
static inline CpaStatus
getReadyMetadataCache(Cpa16U size)
{
        CpaStatus status = CPA_STATUS_FAIL;
        unsigned long flags;

        /* lock for reading and check */
        read_lock(&metadata_cache_lock);

        if (likely(metadataCache != NULL))
        {
                status = CPA_STATUS_SUCCESS;
        }

        read_unlock(&metadata_cache_lock);

        if (unlikely(CPA_STATUS_SUCCESS != status))
        {
                /* lock for writing and create, happens only once */
                write_lock_irqsave(&metadata_cache_lock, flags);

                metadataCache = kmem_cache_create("CpaDcMetadata",
                        size, DEFAULT_ALIGN_CACHE,
                        0, NULL);
                if (likely(NULL != metadataCache))
                {
                        printk(KERN_DEBUG LOG_PREFIX "create kernel cache for metadata (%d)\n", size);
                        status = CPA_STATUS_SUCCESS;
                }
                else
                {
                        printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for metadata (%d)\n", size);
                        status = CPA_STATUS_RESOURCE;
                }

                write_unlock_irqrestore(&metadata_cache_lock, flags);
        }

        return status;
}

static inline CpaStatus
CREATE_METADATA(void **ptr)
{
        CpaStatus status = CPA_STATUS_FAIL;

        *ptr = NULL;

        if (likely(NULL != metadataCache))
        {
                void *result = kmem_cache_alloc(metadataCache, GFP_KERNEL);
                if (likely(NULL != result))
                {
                        *ptr = result;
                        status = CPA_STATUS_SUCCESS;
                }
                else
                {
                        status = CPA_STATUS_RESOURCE;
                }
        }

        return status;
}

#define DESTROY_METADATA(ptr) _destroy_metadata(&(ptr))
static inline void
_destroy_metadata(void **ptr)
{
        if (likely(NULL != *ptr))
        {
                if (likely(NULL != metadataCache))
                {
                        kmem_cache_free(metadataCache, *ptr);
                }
                *ptr = NULL;
        }
}

/*******************************************************
 * BufferListPtr N x sizeof(CpaBufferList) (dynamic cache)
 *******************************************************/
static inline CpaStatus
getReadyBufferListPtrCache(Cpa16U size)
{
        CpaStatus status = CPA_STATUS_FAIL;
        unsigned long flags;

        /* lock for reading and check */
        read_lock(&bufferlistptr_cache_lock);

        if (likely(bufferListPtrCache != NULL))
        {
                status = CPA_STATUS_SUCCESS;
        }

        read_unlock(&bufferlistptr_cache_lock);

        if (unlikely(CPA_STATUS_SUCCESS != status))
        {
                /* lock for writing and create, happens only once */
                write_lock_irqsave(&bufferlistptr_cache_lock, flags);

                bufferListPtrCache = kmem_cache_create("CpaDcBufferListPtr",
                        size, DEFAULT_ALIGN_CACHE,
                        0, NULL);
                if (likely(NULL != bufferListPtrCache))
                {
                        printk(KERN_DEBUG LOG_PREFIX "create kernel cache for buffer list pointers (%d)\n", size);
                        status = CPA_STATUS_SUCCESS;
                }
                else
                {
                        printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for buffer list pointers (%d)\n", size);
                        status = CPA_STATUS_RESOURCE;
                }

                write_unlock_irqrestore(&bufferlistptr_cache_lock, flags);
        }

        return status;
}

static inline CpaStatus
CREATE_BUFFERLISTPTR(CpaBufferList ***ptr)
{
        CpaStatus status = CPA_STATUS_FAIL;

        *ptr = NULL;

        if (likely(NULL != bufferListPtrCache))
        {
                void *result = kmem_cache_alloc(bufferListPtrCache, GFP_KERNEL);
                if (likely(NULL != result))
                {
		    	*ptr = (CpaBufferList**)result;
                        status = CPA_STATUS_SUCCESS;
                }
                else
                {
                        status = CPA_STATUS_RESOURCE;
                }
        }

        return status;
}

#define DESTROY_BUFFERLISTPTR(ptr) _destroy_bufferlistptr(&(ptr))
static inline void
_destroy_bufferlistptr(CpaBufferList ***ptr)
{
        if (likely(NULL != *ptr))
        {
                if (likely(NULL != bufferListPtrCache))
                {
                        kmem_cache_free(bufferListPtrCache, *ptr);
                }
                *ptr = NULL;
        }
}

/*******************************************************
 * Intermediate buffers (static cache)
 *******************************************************/
static inline CpaStatus
CREATE_INTERBUFFER(Cpa8U **ptr)
{
        CpaStatus status = CPA_STATUS_FAIL;

        /* set to NULL even if it fails to avoid dealocation issues later */
        *ptr = NULL;

        if (likely(NULL != interBufferCache))
        {
                void *result = kmem_cache_alloc(interBufferCache, GFP_KERNEL);
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

        return (status);
}

#define DESTROY_INTERBUFFER(pBuffer) _destroy_interbuffer(&(pBuffer))
static inline void
_destroy_interbuffer(Cpa8U **ptr)
{
        if (likely(NULL != *ptr))
        {
                if (likely(NULL != interBufferCache))
                {
                        kmem_cache_free(interBufferCache, *ptr);
                }
                *ptr = NULL;
        }
}

static void
releaseInstanceInfo(qat_instance_info_t *info)
{
	Cpa16U bufferNum;

	if (likely(info->instanceStarted))
	{
		cpaDcStopInstance(info->dcInstHandle);
	}

	info->instanceStarted = CPA_FALSE;
	info->instanceReady = CPA_FALSE;

	/* Free intermediate buffers */
	if (likely(info->bufferInterArray != NULL))
	{
		for (bufferNum = 0; bufferNum < info->numInterBuffLists; bufferNum++)
		{
			if (likely(info->bufferInterArray[bufferNum] != NULL))
			{
				if (likely(info->bufferInterArray[bufferNum]->pBuffers != NULL))
				{
					// PHYS_CONTIG_FREE(info->bufferInterArray[bufferNum]->pBuffers->pData);
					DESTROY_INTERBUFFER(info->bufferInterArray[bufferNum]->pBuffers->pData);
					// PHYS_CONTIG_FREE(info->bufferInterArray[bufferNum]->pBuffers);
					DESTROY_FLATBUFFER(info->bufferInterArray[bufferNum]->pBuffers);
				}
				// PHYS_CONTIG_FREE(info->bufferInterArray[bufferNum]->pPrivateMetaData);
				DESTROY_METADATA(info->bufferInterArray[bufferNum]->pPrivateMetaData);
				// PHYS_CONTIG_FREE(info->bufferInterArray[bufferNum]);
				DESTROY_BUFFERLIST(info->bufferInterArray[bufferNum]);
			}
		}
		// PHYS_CONTIG_FREE(info->bufferInterArray);
		DESTROY_BUFFERLISTPTR(info->bufferInterArray);
	}

}

static CpaStatus
getReadyInstanceInfo(const CpaInstanceHandle dcInstHandle, int instNum, qat_instance_info_t *info)
{
	CpaStatus status = CPA_STATUS_FAIL;
	CpaDcInstanceCapabilities *pCap = NULL;
	Cpa16U bufferNum;
	Cpa32U buffMetaSize = 0;

	/* Implementation requires an intermediate buffer approximately
                           twice the size of the output buffer */
	Cpa32U bufSize = 2 * QAT_MAX_BUF_SIZE;

	if (info->instanceReady)
	{
		status = CPA_STATUS_SUCCESS;
	}
	else
	{

		/* prepare header/footer buffers once */
		info->headerBuf.pData = info->headerData;
		info->headerBuf.dataLenInBytes = ZLIB_HEAD_SZ;
		info->footerBuf.pData = info->footerData;
		info->footerBuf.dataLenInBytes = ZLIB_FOOT_SZ;

		status = VIRT_ALLOC(&pCap, sizeof(CpaDcInstanceCapabilities));
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			printk(KERN_CRIT LOG_PREFIX "failed to allocate memory for capabilities, size=%lu (status=%d)\n",
					sizeof(CpaDcInstanceCapabilities), status);
			goto failed;
		}

		/* Query Capabilities */
		status = cpaDcQueryCapabilities(dcInstHandle, pCap);
		if (unlikely(status != CPA_STATUS_SUCCESS))
		{
			printk(KERN_CRIT LOG_PREFIX "failed to get instance capabilities (status=%d)\n", status);
			goto failed;
		}

		if (unlikely(!pCap->statelessDeflateDecompression ||
				!pCap->statelessDeflateCompression ||
				!pCap->checksumAdler32 ||
				!pCap->dynamicHuffman))
		{
			printk(KERN_CRIT LOG_PREFIX "unsupported functionality\n");
			status = CPA_STATUS_FAIL;
			goto failed;
		}

		info->capable = CPA_TRUE;
		info->autoSelectBestHuffmanTree = pCap->autoSelectBestHuffmanTree;

		if (likely(CPA_STATUS_SUCCESS == status && pCap->dynamicHuffmanBufferReq))
		{
			status = cpaDcBufferListGetMetaSize(dcInstHandle, 1, &buffMetaSize);

			if (CPA_STATUS_SUCCESS == status)
			{
				status = cpaDcGetNumIntermediateBuffers(dcInstHandle, &info->numInterBuffLists);
			}

			if (likely(CPA_STATUS_SUCCESS == status))
			{
				status = getReadyMetadataCache(buffMetaSize);
			}

                        if (CPA_STATUS_SUCCESS == status && 0 != info->numInterBuffLists)
                        {
                            status = getReadyBufferListPtrCache(info->numInterBuffLists * sizeof(CpaBufferList *));
                        }

			if (CPA_STATUS_SUCCESS == status && 0 != info->numInterBuffLists)
			{
			    	// dyn cache
				// status = PHYS_CONTIG_ALLOC(&info->bufferInterArray, info->numInterBuffLists * sizeof(CpaBufferList *));
				status = CREATE_BUFFERLISTPTR(&info->bufferInterArray);
			}

			for (bufferNum = 0; bufferNum < info->numInterBuffLists; bufferNum++)
			{
				if (likely(CPA_STATUS_SUCCESS == status))
				{
					// static cache
					// status = PHYS_CONTIG_ALLOC(&info->bufferInterArray[bufferNum], sizeof(CpaBufferList));
					status = CREATE_BUFFERLIST(&info->bufferInterArray[bufferNum]);
				}
				else
				{
					break;
				}

				if (likely(CPA_STATUS_SUCCESS == status))
				{
					// dyn cache
					// status = PHYS_CONTIG_ALLOC(&info->bufferInterArray[bufferNum]->pPrivateMetaData, buffMetaSize);
					status = CREATE_METADATA(&info->bufferInterArray[bufferNum]->pPrivateMetaData);
				}
				else
				{
					break;
				}

				if (likely(CPA_STATUS_SUCCESS == status))
				{
					// status = PHYS_CONTIG_ALLOC(&info->bufferInterArray[bufferNum]->pBuffers, sizeof(CpaFlatBuffer));
					status = CREATE_FLATBUFFER(&info->bufferInterArray[bufferNum]->pBuffers);
				}
				else
				{
					break;
				}

				if (likely(CPA_STATUS_SUCCESS == status)) {
					/* Implementation requires an intermediate buffer approximately
                                        	twice the size of the output buffer */
					// status = PHYS_CONTIG_ALLOC(&info->bufferInterArray[bufferNum]->pBuffers->pData, bufSize);
					status = CREATE_INTERBUFFER(&info->bufferInterArray[bufferNum]->pBuffers->pData);
					info->bufferInterArray[bufferNum]->numBuffers = 1;
					info->bufferInterArray[bufferNum]->pBuffers->dataLenInBytes = bufSize;
				}
				else
				{
					break;
				}

			} /* End numInterBuffLists */

			if (unlikely(CPA_STATUS_SUCCESS != status))
			{
				printk(KERN_ALERT LOG_PREFIX "failed allocating %d intermediate buffers of size %d and metasize %d\n",
						info->numInterBuffLists, bufSize, buffMetaSize);
				QAT_STAT_BUMP(err_out_of_mem);
			}
		}

		/*
		 * Set the address translation function for the instance
		 */
		if (likely(CPA_STATUS_SUCCESS == status))
		{
			status = cpaDcSetAddressTranslation(dcInstHandle, (void *)virt_to_phys);
		}

		/* Start DataCompression instance */
		if (likely(CPA_STATUS_SUCCESS == status))
		{
			status = cpaDcStartInstance(dcInstHandle, info->numInterBuffLists, info->bufferInterArray);
			if (unlikely(CPA_STATUS_SUCCESS != status))
			{
				printk(KERN_CRIT LOG_PREFIX "failed to start instance with %d buffers of %d (+%d metasize) (status=%d)\n",
						info->numInterBuffLists, bufSize, buffMetaSize, status);
			}
		}

		if (likely(CPA_STATUS_SUCCESS == status))
		{
			info->dcInstHandle = dcInstHandle;
			info->instNum = instNum;
			info->instanceStarted = CPA_TRUE;
		}

		if (likely(CPA_STATUS_SUCCESS == status))
		{
			status = isInstancePolled(dcInstHandle, &info->polled);
		}

		if (likely(CPA_STATUS_SUCCESS == status))
		{
			/* Register callback function for the instance */
			if (likely(info->polled))
			{
				status = cpaDcDpRegCbFunc(dcInstHandle, qat_dc_callback_polled);
			}
			else
			{
				status = cpaDcDpRegCbFunc(dcInstHandle, qat_dc_callback_interrupt);
			}
		}

		if (likely(CPA_STATUS_SUCCESS == status))
		{
			// printk(KERN_DEBUG LOG_PREFIX "instance %d is ready\n", info->instNum);
			info->instanceReady = CPA_TRUE;
		}
	}

failed:

	VIRT_FREE(pCap);

	return (status);
}

/* clean just created structure */
static void
cacheConstructor(void *pOpData)
{
	memset(pOpData, 0, sizeof(CpaDcDpOpData));
}

int
qat_compress_init(void)
{
	Cpa16U numInstances = 0;
	CpaStatus status = CPA_STATUS_FAIL;

	/* max size of output buffer on compression is the max size of buffers used */
	int bufferSize = ceil( 9 * QAT_MAX_BUF_SIZE, 8 ) + 55;

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

	/* use caches to avoid kernel memory fragmentation */
	opCache = kmem_cache_create("CpaDcDpOpData",
			sizeof(CpaDcDpOpData),
			8, SLAB_TEMPORARY|SLAB_CACHE_DMA,
			cacheConstructor);
	if (unlikely(NULL == opCache))
	{
		printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for Op Data (%ld)\n",
				sizeof(CpaDcDpOpData));
		goto err;
	}

	bufferCache = kmem_cache_create("CpaDcBuffers",
			bufferSize,
			DEFAULT_ALIGN_CACHE, SLAB_TEMPORARY, NULL);
	if (unlikely(NULL == bufferCache))
	{
		printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for input/output buffers (%d)\n",
				bufferSize);
		goto err;
	}

	interBufferCache = kmem_cache_create("CpaDcInterBuffer",
			2 * QAT_MAX_BUF_SIZE,
			DEFAULT_ALIGN_CACHE,
			0, NULL);
	if (unlikely(NULL == interBufferCache))
	{
		printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for intermediate buffers (%d)\n",
				2 * QAT_MAX_BUF_SIZE);
		goto err;
	}

        flatbufferCache = kmem_cache_create("CpaDcFlatBuffer",
                sizeof(CpaFlatBuffer),
                DEFAULT_ALIGN_CACHE, 0, NULL);
        if (unlikely(NULL == flatbufferCache))
        {
            printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for flat buffers (%ld)\n", sizeof(CpaFlatBuffer));
            goto err;
        }

        bufferListCache = kmem_cache_create("CpaDcBufferList",
                sizeof(CpaBufferList),
                DEFAULT_ALIGN_CACHE, 0, NULL);
        if (unlikely(NULL == bufferListCache))
        {
            printk(KERN_CRIT LOG_PREFIX "failed to allocate kernel cache for buffer lists (%ld)\n", sizeof(CpaBufferList));
            goto err;
        }

	/* install statistics at /proc/spl/kstat/zfs/qat-dc */
	qat_ksp = kstat_create("zfs", 0, "qat-dc", "misc",
			KSTAT_TYPE_NAMED, sizeof (qat_dc_stats) / sizeof (kstat_named_t),
			KSTAT_FLAG_VIRTUAL);

	if (unlikely(NULL == qat_ksp))
	{
		printk(KERN_CRIT LOG_PREFIX "failed to allocate statistics\n");
		goto err;
	}

	qat_ksp->ks_data = &qat_dc_stats;
	kstat_install(qat_ksp);

	if (unlikely(CPA_STATUS_SUCCESS == cpaDcGetNumInstances(&numInstances) && numInstances > 0))
	{
		printk(KERN_INFO LOG_PREFIX "started with %ld DC instances\n",
				min((long)numInstances, (long)MAX_INSTANCES));
	}
	else
	{
		printk(KERN_INFO LOG_PREFIX "initialized\n");
	}

	spin_lock_init(&next_instance_lock);
	spin_lock_init(&compression_time_lock);
	spin_lock_init(&decompression_time_lock);

	// rwlock_init(&instance_storage_lock);
	rwlock_init(&session_cache_lock);
	rwlock_init(&metadata_cache_lock);
	rwlock_init(&bufferlistptr_cache_lock);

	getnstimeofday(&engineStarted);
	atomic_inc(&initialized);

	return 0;

err:

	printk(KERN_ALERT LOG_PREFIX "initialization failed\n");

	return 0;
}

void
qat_compress_fini(void)
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

	// caches are created in init
	DESTROY_CACHE(opCache);
	DESTROY_CACHE(bufferCache);
	DESTROY_CACHE(interBufferCache);
	DESTROY_CACHE(flatbufferCache);
	DESTROY_CACHE(bufferListCache);

	// caches are created dynamically
	write_lock_irqsave(&session_cache_lock, flags);
	DESTROY_CACHE(sessionCache);
	write_unlock_irqrestore(&session_cache_lock, flags);

	write_lock_irqsave(&metadata_cache_lock, flags);
	DESTROY_CACHE(metadataCache);
	write_unlock_irqrestore(&metadata_cache_lock, flags);

	write_lock_irqsave(&bufferlistptr_cache_lock, flags);
	DESTROY_CACHE(bufferListPtrCache);
	write_unlock_irqrestore(&bufferlistptr_cache_lock, flags);

}

boolean_t
qat_use_accel(const qat_compress_dir_t dir, const size_t s_len)
{
	boolean_t ret = B_FALSE;

	if (zfs_qat_disable == 0 && atomic_read(&initialized) != 0)
	{
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


static inline unsigned long
getTimeoutMs(const int dataSize, const int maxSize)
{
	unsigned long timeout = TIMEOUT_MS_MIN + (TIMEOUT_MS_MAX - TIMEOUT_MS_MIN) * dataSize / maxSize;
	return timeout;
}

// WARNING: allocate at least CPA_INST_NAME_SIZE + 1 bytes for instance name
static CpaStatus
getInstanceName(const CpaInstanceHandle dcInstHandle, Cpa8U *instName)
{
	CpaStatus status;
	CpaInstanceInfo2 *instanceInfo = NULL;

	status = VIRT_ALLOC(&instanceInfo, sizeof(CpaInstanceInfo2));

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		// get name of instance
		status = cpaDcInstanceGetInfo2(dcInstHandle, instanceInfo);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		strncpy(instName, instanceInfo->instName, CPA_INST_NAME_SIZE);
	}

	VIRT_FREE(instanceInfo);

	return status;
}

static CpaStatus
waitForCompletion(const CpaInstanceHandle dcInstHandle, const CpaDcDpOpData *pOpData, const CpaBoolean polled, const unsigned long timeoutMs)
{
	CpaStatus status = CPA_STATUS_SUCCESS;
	Cpa8U *instanceName = NULL;

	if (likely(polled))
	{
		/* Poll for responses */
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
 * Loading available DC instances and select next one (locked with instance number)
 */
static inline CpaStatus
getInstance(CpaInstanceHandle *instance, int *instanceNum)
{
	CpaStatus status = CPA_STATUS_SUCCESS;
	Cpa16U num_inst = 0;
	int inst = 0;
	CpaBoolean instanceFound = CPA_FALSE;

	CpaInstanceHandle *handles = NULL;

	status = cpaDcGetNumInstances(&num_inst);
	if (unlikely(status != CPA_STATUS_SUCCESS))
	{
		/* show message once in a minute */
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
		/* return success but no instances configured */
		if (unlikely(num_inst == 0))
		{
			/* show message once in a minute */
			if (jiffies_to_msecs(jiffies - atomic_long_read(&getInstanceMessageShown)) > 60L * 1000L)
			{
				printk(KERN_ALERT LOG_PREFIX "no instances found, please configure NumberDcInstances in [KERNEL_QAT] section\n");
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

	status = cpaDcGetInstances(num_inst, handles);
	if (unlikely(status != CPA_STATUS_SUCCESS))
	{
		printk(KERN_CRIT LOG_PREFIX "failed loading instances, num_inst=%d (status=%d)\n", num_inst, status);
		goto done;
	}

	/* search for next available instance */
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
			printk(KERN_WARNING LOG_PREFIX "failed to find free DC instance ouf of %d, consider to increase NumberDcInstances in [KERNEL_QAT] section\n", num_inst);
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

/*
 * This function performs a decompression operation.
 */
static qat_compress_status_t
compPerformOp(qat_instance_info_t *info, const CpaDcSessionHandle sessionHdl,
		const char* src, const int src_len,
		char* dest, const int dest_len, size_t *c_len)
{

	const CpaInstanceHandle dcInstHandle = info->dcInstHandle;
	const CpaBoolean polled = info->polled;

	qat_compress_status_t ret = QAT_COMPRESS_FAIL;
	CpaStatus status = CPA_STATUS_SUCCESS;

	struct completion *pComplete = NULL;
	unsigned long timeout = 0;

	/* flatbuffer is not necessary here but very convenient */
	CpaFlatBuffer srcBuf = {0};
	CpaFlatBuffer destBuf = {0};

	/*
	 * recovery from errors is more expensive then successful compression
	 * therefore set the size of output buffer by Intel's recomendation
	 * Destination buffer size in bytes = ceil(9 * Total input bytes / 8) + 55 bytes
	 */
	Cpa32U bufferSize = ceil( 9 * src_len, 8 ) + 55;

	CpaDcDpOpData *pOpData = NULL;

	Cpa32U hdr_sz = 0;
	Cpa32U foot_sz = 0;
	Cpa32U compressed_sz = 0;

	QAT_STAT_BUMP(comp_requests);
	QAT_STAT_INCR(comp_total_in_bytes, src_len);

	if (unlikely(CPA_STATUS_SUCCESS == status && !polled))
	{
		status = VIRT_ALLOC(&pComplete, sizeof(struct completion));
	}

	/* allocate source buffer */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		// status = PHYS_CONTIG_ALLOC_ALIGNED(&srcBuf.pData, src_len, DEFAULT_ALIGN_ALLOC);
		status = CREATE_BUFFER(&srcBuf.pData);
		srcBuf.dataLenInBytes = src_len;
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			printk(KERN_WARNING LOG_PREFIX "compression failed to allocate %d bytes for input buffer\n",
					src_len);
			QAT_STAT_BUMP(err_out_of_mem);
		}
	}

	/* allocate destination buffer */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		memcpy(srcBuf.pData, src, src_len);

		// status = PHYS_CONTIG_ALLOC_ALIGNED(&destBuf.pData, bufferSize, DEFAULT_ALIGN_ALLOC);
		status = CREATE_BUFFER(&destBuf.pData);
		destBuf.dataLenInBytes = bufferSize;
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			printk(KERN_WARNING LOG_PREFIX "compression failed to allocate %d bytes for output buffer\n",
					bufferSize);
			QAT_STAT_BUMP(err_out_of_mem);
		}
	}

	/* generate header */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		// generate header into own buffer
		status = cpaDcGenerateHeader(sessionHdl, &info->headerBuf, &hdr_sz);
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			QAT_STAT_BUMP(err_gen_header);
			printk(KERN_CRIT LOG_PREFIX "failed to generate header into buffer of size %d (status=%d)\n",
					info->headerBuf.dataLenInBytes, status);
		}
	}

	/* allocate pOpData */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/* Allocate memory for operational data. Note this needs to be
		 * 8-byte aligned, contiguous, resident in DMA-accessible
		 * memory.
		 */
		status = CREATE_OPDATA(&pOpData);
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			printk(KERN_WARNING LOG_PREFIX "compression failed to allocate opdata\n");
			QAT_STAT_BUMP(err_out_of_mem);
		}
	}

	// submit operation
	if (likely(CPA_STATUS_SUCCESS == status))
	{
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

		if (likely(polled))
		{
			pOpData->pCallbackTag = (void *)0;
		}
		else
		{
			init_completion(pComplete);
			pOpData->pCallbackTag = (void *)pComplete;
		}

		/** Enqueue and submit operation */
		status = cpaDcDpEnqueueOp(pOpData, CPA_TRUE);
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			register_error_status(status);
			printk(KERN_CRIT LOG_PREFIX "compression job submit failed (status = %d)\n", status);
		}
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		// wait for bigger packets longer but at least 0.5 sec
		timeout = getTimeoutMs(dest_len, QAT_MAX_BUF_SIZE_COMP);
		status = waitForCompletion(dcInstHandle, pOpData, polled, timeout);
	}

	/*
	 * We now check the results
	 */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		if (unlikely(pOpData->responseStatus != CPA_STATUS_SUCCESS))
		{
			register_op_status(pOpData->results.status);

			/* overflow is normal condition, don't interpret as failure */
			if (pOpData->results.status == CPA_DC_OVERFLOW)
			{
				ret = QAT_COMPRESS_UNCOMPRESSIBLE;
			}
			else
			{
				register_error_status(pOpData->responseStatus);
				printk(KERN_ERR LOG_PREFIX "compression of %d to %d failed (status = %d)\n",
						src_len, dest_len, pOpData->responseStatus);
			}

			status = CPA_STATUS_FAIL;
		}
		else
		{
			if (unlikely(pOpData->results.status != CPA_DC_OK))
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

				/* if result is already bigger then buffer+header, no need to generate footer */
				if (pOpData->results.produced + hdr_sz > dest_len)
				{
					QAT_STAT_BUMP(err_overflow);
#if QAT_DEBUG
					printk(KERN_DEBUG LOG_PREFIX "compression of %d produced output of %d (+%d header) bytes but output buffer is only %d\n",
							src_len, pOpData->results.produced, hdr_sz, dest_len);
#endif
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

	// generate footer
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/* generate footer into own buffer but updates pOpData->results */
		status = cpaDcGenerateFooter(sessionHdl, &info->footerBuf, &pOpData->results);
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			QAT_STAT_BUMP(err_gen_footer);
			printk(KERN_CRIT LOG_PREFIX "failed to generate footer into buffer of size %d (status=%d)\n",
					info->footerBuf.dataLenInBytes, status);
		}
	}

	/* store results into destination */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/* compressed data + footer */
		foot_sz = pOpData->results.produced - compressed_sz;

		if (hdr_sz + compressed_sz + foot_sz > dest_len) {

			QAT_STAT_BUMP(err_overflow);
#if QAT_DEBUG
			printk(KERN_DEBUG LOG_PREFIX "compression of %d produced output of %d (+%d header, +%d footer) bytes but output buffer is only %d\n",
					src_len, compressed_sz, hdr_sz, foot_sz, dest_len);
#endif
			ret = QAT_COMPRESS_UNCOMPRESSIBLE;
			status = CPA_STATUS_FAIL;

		} else {

			/* copy header+output+footer into destination */
			memcpy(&dest[0], 	  		info->headerBuf.pData,	hdr_sz);
			memcpy(&dest[hdr_sz], 			destBuf.pData,		compressed_sz);
			memcpy(&dest[hdr_sz + compressed_sz],	info->footerBuf.pData,	foot_sz);

			/* save size of compressed data */
			*c_len = hdr_sz + compressed_sz + foot_sz;

			QAT_STAT_INCR(comp_total_out_bytes, *c_len);
			QAT_STAT_INCR(comp_total_success_bytes, src_len);

			ret = QAT_COMPRESS_SUCCESS;
		}
	}

	if (unlikely(CPA_STATUS_SUCCESS != status))
	{
		QAT_STAT_BUMP(comp_fails);
	}

	/*
	 * Free the memory!
	 */

	DESTROY_OPDATA(pOpData);

	// PHYS_CONTIG_FREE(srcBuf.pData);
	// PHYS_CONTIG_FREE(destBuf.pData);
	DESTROY_BUFFER(srcBuf.pData);
	DESTROY_BUFFER(destBuf.pData);

	VIRT_FREE(pComplete);

	return ret;

}

/*
 * This function performs a decompression operation.
 */
static qat_compress_status_t
decompPerformOp(qat_instance_info_t *info, const CpaDcSessionHandle sessionHdl,
		const char* src, const int src_len,
		char* dest, const int dest_len, size_t *c_len)
{

	qat_compress_status_t ret = QAT_COMPRESS_FAIL;
	CpaStatus status = CPA_STATUS_SUCCESS;

	const CpaInstanceHandle dcInstHandle = info->dcInstHandle;
	const CpaBoolean polled = info->polled;

	struct completion *pComplete = NULL;
	unsigned long timeout = 0;

	/* flatbuffer is not necessary here but very convenient */
	CpaFlatBuffer srcBuf = {0};
	CpaFlatBuffer destBuf = {0};

	/*
	 * For decompression operations, the minimal destination buffer size should be 258 bytes.
	 * QATE-30865
	 */
	const Cpa32U bufferSize = max(258L, (long)dest_len);

	CpaDcDpOpData *pOpData = NULL;

	QAT_STAT_BUMP(decomp_requests);
	QAT_STAT_INCR(decomp_total_in_bytes, src_len);

	if (unlikely(CPA_STATUS_SUCCESS == status && !polled))
	{
		status = VIRT_ALLOC(&pComplete, sizeof(struct completion));
	}

	/* allocate source buffer */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		// status = PHYS_CONTIG_ALLOC_ALIGNED(&srcBuf.pData, src_len - ZLIB_HEAD_SZ, DEFAULT_ALIGN_ALLOC);
		status = CREATE_BUFFER(&srcBuf.pData);
		srcBuf.dataLenInBytes = src_len - ZLIB_HEAD_SZ;
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			printk(KERN_WARNING LOG_PREFIX "decompression failed to allocate %d bytes for input buffer\n",
					src_len - ZLIB_HEAD_SZ);
			QAT_STAT_BUMP(err_out_of_mem);
		}
	}

	/* allocate destination buffer */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		memcpy(srcBuf.pData, &src[ZLIB_HEAD_SZ], src_len - ZLIB_HEAD_SZ);

		// status = PHYS_CONTIG_ALLOC_ALIGNED(&destBuf.pData, bufferSize, DEFAULT_ALIGN_ALLOC);
		status = CREATE_BUFFER(&destBuf.pData);
		destBuf.dataLenInBytes = bufferSize;
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			printk(KERN_WARNING LOG_PREFIX "decompression failed to allocate %d bytes for output buffer\n",
					bufferSize);
			QAT_STAT_BUMP(err_out_of_mem);
		}
	}

	/* allocate pOpData */
	if (likely(CPA_STATUS_SUCCESS == status))
	{

		/* Allocate memory for operational data. Note this needs to be
		 * 8-byte aligned, contiguous, resident in DMA-accessible
		 * memory.
		 */
		status = CREATE_OPDATA(&pOpData);
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			printk(KERN_WARNING LOG_PREFIX "decompression failed to allocate opdata\n");
			QAT_STAT_BUMP(err_out_of_mem);
		}
	}

	// submit operation
	if (likely(CPA_STATUS_SUCCESS == status))
	{
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

		if (likely(polled))
		{
			pOpData->pCallbackTag = (void *)0;
		}
		else
		{
			init_completion(pComplete);
			pOpData->pCallbackTag = (void *)pComplete;
		}

		/** Enqueue and submit operation */
		status = cpaDcDpEnqueueOp(pOpData, CPA_TRUE);
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			register_error_status(status);
			printk(KERN_CRIT LOG_PREFIX "decompression job submit failed (status = %d)\n", status);
		}
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/* wait for bigger packets longer but at lease 0.5 sec */
		timeout = getTimeoutMs(dest_len, QAT_MAX_BUF_SIZE_DECOMP);
		status = waitForCompletion(dcInstHandle, pOpData, polled, timeout);
	}

	/*
	 * We now check the results
	 */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		if (unlikely(pOpData->responseStatus != CPA_STATUS_SUCCESS))
		{
			register_error_status(pOpData->responseStatus);
			register_op_status(pOpData->results.status);

			printk(KERN_ERR LOG_PREFIX "decompression operation failed with op_status=%d (status = %d)\n",
					pOpData->results.status, pOpData->responseStatus);

			status = CPA_STATUS_FAIL;
		}
		else
		{
			if (unlikely(pOpData->results.status != CPA_DC_OK))
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

				if (unlikely(pOpData->results.produced > dest_len))
				{
					QAT_STAT_BUMP(err_overflow);
					printk(KERN_ERR LOG_PREFIX "decompression of %d produced output of %d bytes but output buffer is only %d\n",
							src_len, pOpData->results.produced, dest_len);
					status = CPA_STATUS_FAIL;

				}
				else
				{
					/* copy data from output buffer to destination */
					memcpy(dest, destBuf.pData, pOpData->results.produced);

					// save result size
					*c_len = pOpData->results.produced;

					QAT_STAT_INCR(decomp_total_out_bytes, *c_len);
					QAT_STAT_INCR(decomp_total_success_bytes, src_len);

					ret = QAT_COMPRESS_SUCCESS;
				}
			}
		}
	}

	if (unlikely(CPA_STATUS_SUCCESS != status))
	{
		QAT_STAT_BUMP(decomp_fails);
	}

	/*
	 * Free the memory!
	 */
	DESTROY_OPDATA(pOpData);

	// PHYS_CONTIG_FREE(srcBuf.pData);
	// PHYS_CONTIG_FREE(destBuf.pData);
	DESTROY_BUFFER(srcBuf.pData);
	DESTROY_BUFFER(destBuf.pData);

	VIRT_FREE(pComplete);

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

	// above level 6 no significant compression ratio increase observed
	return CPA_DC_L6;
}


/*************************************************************************
 *
 * QAT Compression/Decompression action
 *
 *************************************************************************/
static qat_compress_status_t
qat_action( qat_compress_status_t (*func)(qat_instance_info_t*, const CpaDcSessionHandle sessionHdl, const char*, const int, char*, const int, size_t*),
		const int level, const char* src, const int src_len, char* dest, const int dest_len, size_t *c_len)
{

	qat_compress_status_t ret = QAT_COMPRESS_FAIL;

	int instNum;

	CpaStatus status = CPA_STATUS_SUCCESS;
	CpaDcSessionHandle sessionHdl = NULL;
	CpaInstanceHandle dcInstHandle = NULL;

	CpaDcSessionSetupData *pSd = NULL;
	Cpa32U sess_size = 0;
	Cpa32U ctx_size = 0;

	/*
	 * In this simplified version of instance discovery, we discover
	 * exactly one instance of a data compression service.
	 * Note this is the same as was done for "traditional" api.
	 */
	status = getInstance(&dcInstHandle, &instNum);
	if (status != CPA_STATUS_SUCCESS || dcInstHandle == NULL)
	{
		goto failed;
	}

	status = getReadyInstanceInfo(dcInstHandle, instNum, &instances[instNum]);
	if (CPA_STATUS_SUCCESS != status)
	{
		goto failed;
	}

	/* drop counter after successfull init */
	atomic_set(&numInitFailed, 0);

	if (likely(CPA_STATUS_SUCCESS == status))
	{
	    status = VIRT_ALLOC(&pSd, sizeof(CpaDcSessionSetupData));
	}

	/*
	 * We now populate the fields of the session operational data and create
	 * the session.  Note that the size required to store a session is
	 * implementation-dependent, so we query the API first to determine how
	 * much memory to allocate, and then allocate that memory.
	 */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		memset(pSd, 0, sizeof(CpaDcSessionSetupData));

		/* ignored by decompression */
		pSd->compLevel = compLevel(level);
		pSd->compType = CPA_DC_DEFLATE;
		pSd->huffType = CPA_DC_HT_FULL_DYNAMIC;
		/* If the implementation supports it, the session will be configured
		 * to select static Huffman encoding over dynamic Huffman as
		 * the static encoding will provide better compressibility.
		 */
		if (instances[instNum].autoSelectBestHuffmanTree)
		{
			pSd->autoSelectBestHuffmanTree = CPA_TRUE;
		}
		else
		{
			pSd->autoSelectBestHuffmanTree = CPA_FALSE;
		}
		pSd->sessDirection = CPA_DC_DIR_COMBINED;
		pSd->sessState = CPA_DC_STATELESS;
#if (CPA_DC_API_VERSION_NUM_MAJOR == 1 && CPA_DC_API_VERSION_NUM_MINOR < 6)
		pSd->deflateWindowSize = 7;
#endif
		pSd->checksum = CPA_DC_ADLER32;

		/* Determine size of session context to allocate */
		status = cpaDcGetSessionSize(dcInstHandle, pSd, &sess_size, &ctx_size);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		status = getReadySessionCache(sess_size);
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		/* Allocate session memory */
		status = CREATE_SESSION(&sessionHdl);
	}

	/* Initialize the Stateless session */
	if (likely(CPA_STATUS_SUCCESS == status))
	{
		status = cpaDcDpInitSession(dcInstHandle,
			sessionHdl, /* session memory */
			pSd);       /* session setup data */
		if (unlikely(CPA_STATUS_SUCCESS != status))
		{
			printk(KERN_CRIT LOG_PREFIX "failed to init session (status=%d)\n", status);
		}
	}

	if (likely(CPA_STATUS_SUCCESS == status))
	{
		CpaStatus sessionStatus = CPA_STATUS_SUCCESS;

	        /* perform Comp/decompression operation */
		ret = (*func)(&instances[instNum], sessionHdl, src, src_len, dest, dest_len, c_len);

		sessionStatus = cpaDcDpRemoveSession(dcInstHandle, sessionHdl);

		/* Maintain status of remove session only when status of all operations
		 * before it are successful. */
		if (likely(CPA_STATUS_SUCCESS == status))
		{
			status = sessionStatus;
		}
	}

	/*
	 * Free up memory, stop the instance, etc.
	 */

	/* Free session Context */
	DESTROY_SESSION(sessionHdl);

	/* free temporary allocations */
	VIRT_FREE(pSd);

	/* to have more free memory, unlock instance after cleaning */

	unlock_instance(instNum);

	return ret;

/* go here before any initializations */
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
		ret = qat_action(compPerformOp, level, src, src_len, dest, dest_len, c_len);
		if (likely(QAT_COMPRESS_SUCCESS == ret))
		{
			/* update stats once per second */
			if (0 == zfs_qat_disable_dc_benchmark) //  && jiffies_to_msecs(jiffies - atomic_long_read(&lastCompThUpdate)) > 1000)
			{
				updateThroughputComp(start, jiffies);
				// atomic_long_set(&lastCompThUpdate, jiffies);
			}
		}
		break;

	case QAT_DECOMPRESS:
		ret = qat_action(decompPerformOp, level, src, src_len, dest, dest_len, c_len);
		if (likely(QAT_COMPRESS_SUCCESS == ret))
		{
			if (0 == zfs_qat_disable_dc_benchmark) // && jiffies_to_msecs(jiffies-atomic_long_read(&lastDecompThUpdate)) > 1000)
			{
				updateThroughputDecomp(start, jiffies);
				// atomic_long_set(&lastDecompThUpdate, jiffies);
			}
		}
		break;

	default:
		/* not possible */
		break;
	}

	return ret;
}

module_param(zfs_qat_disable_dc_benchmark, int, 0644);
MODULE_PARM_DESC(zfs_qat_disable_dc_benchmark, "Disable data compression benchmark");

module_param(zfs_qat_disable_compression, int, 0644);
MODULE_PARM_DESC(zfs_qat_disable_compression, "Disable QAT compression");

module_param(zfs_qat_disable_decompression, int, 0644);
MODULE_PARM_DESC(zfs_qat_disable_decompression, "Disable QAT decompression");

#endif
