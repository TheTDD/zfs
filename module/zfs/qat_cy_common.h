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

#include "qat_digest.h"

/* Check for CY API version */
#define CY_API_VERSION_AT_LEAST(major, minor)                                  \
    (CPA_CY_API_VERSION_NUM_MAJOR > major ||                                   \
         (CPA_CY_API_VERSION_NUM_MAJOR == major &&                                 \
               CPA_CY_API_VERSION_NUM_MINOR >= minor))

/* maximum number of Cy-Sym instances on one QAT controller */
#define MAX_INSTANCES 128

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

/*
 * Used for qat kstat.
 */
typedef struct qat_stats_cy
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
	kstat_named_t sha2_256_requests_per_second;

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
	kstat_named_t sha3_256_requests_per_second;

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
	kstat_named_t err_status_restarting;
	kstat_named_t err_status_unknown;

} qat_stats_cy_t;

#define QAT_STAT_INCR(stat, val) \
                atomic_add_64(&qat_cy_stats.stat.value.ui64, (val))
#define QAT_STAT_BUMP(stat) \
                atomic_inc_64(&qat_cy_stats.stat.value.ui64)

typedef struct qat_instance_info
{
	CpaInstanceHandle cyInstHandle;
	CpaBoolean instanceStarted;
	CpaBoolean instanceReady;
	CpaBoolean polled;
	int instNum;
} qat_instance_info_t;

int getNextInstance(const Cpa16U num_inst);
CpaBoolean check_and_lock(const Cpa16U i);
void unlock_instance(const Cpa16U i);

/*
 * Loading available DC instances and select next one
 */
CpaStatus getInstance(CpaInstanceHandle *instance, int *instanceNum);


/* get type of instance, polled (1) or interrupt (0) */
CpaStatus isInstancePolled(const CpaInstanceHandle dcInstHandle, CpaBoolean *polled);

/* Warning: allocate at least CPA_INST_NAME_SIZE + 1 bytes for instance name */
CpaStatus getInstanceName(const CpaInstanceHandle dcInstHandle, Cpa8U *instName);

/* callbacks */
void qat_cy_callback_interrupt(CpaCySymDpOpData *pOpData, CpaStatus status, CpaBoolean verifyResult);
void qat_cy_callback_polled(CpaCySymDpOpData *pOpData, CpaStatus status, CpaBoolean verifyResult);

void releaseInstanceInfo(qat_instance_info_t *info);
CpaStatus getReadyInstanceInfo(const CpaInstanceHandle cyInstHandle, int instNum, qat_instance_info_t *info);

static inline uint32_t
getTimeoutMs(const int dataSize, const int maxSize)
{
        uint32_t timeout = TIMEOUT_MS_MIN + (TIMEOUT_MS_MAX - TIMEOUT_MS_MIN) * dataSize / maxSize;
        return timeout;
}

CpaStatus waitForCompletion(const CpaInstanceHandle dcInstHandle, const CpaCySymDpOpData *pOpData, const CpaBoolean polled, const unsigned long timeoutMs);
void register_error_status(const CpaStatus status);

static inline void
symSessionWaitForInflightReq(CpaCySymSessionCtx pSessionCtx)
{
        /* Session in use is available since Cryptographic API version 2.2 */
#if CY_API_VERSION_AT_LEAST(2, 2)
        CpaBoolean sessionInUse = CPA_FALSE;
        do
        {
                cpaCySymSessionInUse(pSessionCtx, &sessionInUse);

        } while (sessionInUse);
#endif
        return;
}

/************************************
 * static kernel cache for opData
 ************************************/
CpaStatus CREATE_OPDATA(CpaCySymDpOpData **ptr);

#define DESTROY_OPDATA(pOpData) _destroy_opdata(&(pOpData))
void _destroy_opdata(CpaCySymDpOpData **ptr);

extern qat_instance_info_t *instances;
extern struct timespec engineStarted;
extern atomic_t initialized;
extern qat_stats_cy_t qat_cy_stats;

/* init - deinit */
boolean_t qat_cy_common_init(void);
void qat_cy_common_fini(void);

#else

#define qat_cy_common_init()
#define qat_cy_common_fini()

#endif
