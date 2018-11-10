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

#ifndef	_SYS_QAT_DIGEST_H
#define	_SYS_QAT_DIGEST_H


typedef enum qat_digest_status {
	QAT_DIGEST_SUCCESS = 0,
	QAT_DIGEST_FAIL = 1,
} qat_digest_status_t;

typedef enum qat_digest_type {
	QAT_DIGEST_SHA2_256 = 2,
	QAT_DIGEST_SHA3_256 = 3,
} qat_digest_type_t;

#define SHA2_256_DIGEST_LENGTH 32
#define SHA3_256_DIGEST_LENGTH 32

#if defined(_KERNEL) && defined(HAVE_QAT)
#include <sys/zio.h>
#include <cpa.h>
#include <lac/cpa_cy_sym_dp.h>

#define QAT_DIGEST_ENABLE_SHA3_256	0

extern int qat_digest_init(void);
extern void qat_digest_fini(void);
extern boolean_t qat_digest_use_accel(const qat_digest_type_t type, const size_t s_len);
extern qat_digest_status_t qat_digest(const qat_digest_type_t type, const uint8_t *src, const int size, zio_cksum_t *teml);

/* Check for CY API version */
#define CY_API_VERSION_AT_LEAST(major, minor)                                  \
    (CPA_CY_API_VERSION_NUM_MAJOR > major ||                                   \
         (CPA_CY_API_VERSION_NUM_MAJOR == major &&                                 \
               CPA_CY_API_VERSION_NUM_MINOR >= minor))

#else
#define	CPA_STATUS_SUCCESS	0
#define	qat_digest_init()
#define	qat_digest_fini()
#define	qat_digest_use_accel(type, s_len)	B_FALSE
#define	qat_digest(type, s, sl, d)	QAT_DIGEST_FAIL
#endif

#endif /* _SYS_QAT_DIGEST_H */
