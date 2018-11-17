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

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include <sys/debug.h>
#include <sys/types.h>
#include "qat_compress.h"

#ifdef _KERNEL

#include <sys/systm.h>
#include <sys/zmod.h>

typedef size_t zlen_t;
#define	compress_func	z_compress_level
#define	uncompress_func	z_uncompress

#else /* _KERNEL */

#include <strings.h>
#include <zlib.h>

typedef uLongf zlen_t;
#define	compress_func	compress2
#define	uncompress_func	uncompress

#endif

#include "qat_compress.h"

size_t
gzip_compress(void *s_start, void *d_start, size_t s_len, size_t d_len, int n)
{
	zlen_t dstlen = d_len;
	qat_compress_status_t qatStatus;

	ASSERT(d_len <= s_len);

	/* check if hardware accelerator can be used */
	if (qat_use_accel(QAT_COMPRESS, s_len)) 
	{
		qatStatus = qat_compress(QAT_COMPRESS, n, s_start, s_len, d_start, d_len, &dstlen);
		switch (qatStatus) 
		{
		    case QAT_COMPRESS_SUCCESS:
			return ((size_t)dstlen);

		    case QAT_COMPRESS_UNCOMPRESSIBLE:
			memmove(d_start, s_start, s_len);
			return (s_len);

		    default:
			// continue with software compression
			break;
		}
		/* if hardware compress fail, do it again with software */
	}

	if (compress_func(d_start, &dstlen, s_start, s_len, n) != Z_OK) 
	{
		if (d_len != s_len)
			return (s_len);

		memmove(d_start, s_start, s_len);
		return (s_len);
	}

	return ((size_t)dstlen);
}

/*ARGSUSED*/
int
gzip_decompress(void *s_start, void *d_start, size_t s_len, size_t d_len, int n)
{
	zlen_t dstlen = d_len;
	qat_compress_status_t qatStatus;

	ASSERT(d_len >= s_len);

	/* check if hardware accelerator can be used */
	if (qat_use_accel(QAT_DECOMPRESS, d_len)) 
	{
		qatStatus = qat_compress(QAT_DECOMPRESS, n, s_start, s_len, d_start, d_len, &dstlen);
		switch (qatStatus) 
		{
		    case QAT_COMPRESS_SUCCESS:
			return (0);

		    default:
			// continue with software
			break;
		}
		/* if hardware de-compress fail, do it again with software */
	}

	if (uncompress_func(d_start, &dstlen, s_start, s_len) != Z_OK)
		return (-1);

	return (0);
}
