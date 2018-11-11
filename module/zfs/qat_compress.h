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

#ifndef	_SYS_QAT_COMPRESS_H
#define	_SYS_QAT_COMPRESS_H

typedef enum qat_compress_status {
	QAT_COMPRESS_SUCCESS = 0,
	QAT_COMPRESS_FAIL = 1,
	QAT_COMPRESS_UNCOMPRESSIBLE = 2,
} qat_compress_status_t;

#if defined(_KERNEL) && defined(HAVE_QAT)
#include <sys/zio.h>
typedef enum qat_compress_dir {
	QAT_COMPRESS = 0,
	QAT_DECOMPRESS = 1,
} qat_compress_dir_t;

extern int qat_compress_init(void);
extern void qat_compress_fini(void);
extern boolean_t qat_use_accel(const qat_compress_dir_t dir, const size_t s_len);
extern qat_compress_status_t qat_compress(const qat_compress_dir_t dir, const int level, const char *src, const int src_len,
    char *dst, const int dst_len, size_t *c_len);

#else

#define	qat_compress_init()
#define	qat_compress_fini()
#define	qat_use_accel(dir, s_len)			B_FALSE
#define	qat_compress(dir, lvl, s, sl, d, dl, cl)	QAT_COMPRESS_FAIL

#endif

#endif /* _SYS_QAT_COMPRESS_H */
