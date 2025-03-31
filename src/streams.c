/* SPDX-License-Identifier: MPL-2.0 */
/**********************************************************************
 * Copyright (c) 2025, Siemens AG
 **********************************************************************/

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <gta_api/gta_api.h>
#include <gta_api/util/gta_memset.h>
#include "streams.h"

/*
 * myio_ifilestream reference implementation
 */

GTA_DEFINE_FUNCTION(bool, myio_close_ifilestream,
(
    myio_ifilestream_t * istream,
    gta_errinfo_t * p_errinfo
))
{
    fclose(istream->file);
    gta_memset(istream, sizeof(myio_ifilestream_t),
            0, sizeof(myio_ifilestream_t));
    return true;
}

GTA_DEFINE_FUNCTION(size_t, myio_ifilestream_read,
(
    myio_ifilestream_t * istream,
    char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
))
{
    return fread(data, sizeof(char), len, istream->file);
}

GTA_DEFINE_FUNCTION(bool, myio_ifilestream_eof,
(
    myio_ifilestream_t * istream,
    gta_errinfo_t * p_errinfo
))
{
    return feof(istream->file) != 0 ? true : false;
}

GTA_DEFINE_FUNCTION(bool, myio_open_ifilestream,
(
    myio_ifilestream_t * istream,
    const char * filename,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;
    FILE * file = NULL;

#ifdef WINDOWS
    errno_t err = -1;
    err = fopen_s(&file, filename, "rb");
    if (err == 0)
#else
    if (NULL != (file = fopen(filename, "rb")))
#endif
    {
        istream->read = (gtaio_stream_read_t)myio_ifilestream_read;
        istream->eof = (gtaio_stream_eof_t)myio_ifilestream_eof;
        istream->file = file;
        ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
    }

    return ret;
}

/*
 * myio_ofilestream reference implementation
 */

GTA_DEFINE_FUNCTION(bool, myio_close_ofilestream,
(
    myio_ofilestream_t * ostream,
    gta_errinfo_t * p_errinfo
))
{
    fclose(ostream->file);
    gta_memset(ostream, sizeof(myio_ofilestream_t),
            0, sizeof(myio_ofilestream_t));
    return true;
}

GTA_DEFINE_FUNCTION(size_t, myio_ofilestream_write,
(
    myio_ofilestream_t * ostream,
    char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
))
{
    return fwrite(data, sizeof(char), len, ostream->file);
}

GTA_DEFINE_FUNCTION(bool, myio_ofilestream_finish,
(
    myio_ofilestream_t * ostream,
    gta_errinfo_t errinfo,
    gta_errinfo_t * p_errinfo
    ))
{
    /* todo: what to do with errinfo? */
    return true;
}

GTA_DEFINE_FUNCTION(bool, myio_open_ofilestream,
(
    myio_ofilestream_t * ostream,
    const char * filename,
    gta_errinfo_t * p_errinfo
))
{
    bool ret = false;
    FILE * file = NULL;

#ifdef WINDOWS
    errno_t err = -1;
    err = fopen_s(&file, filename, "wb");
    if (err == 0)
#else
    if (NULL != (file = fopen(filename, "wb")))
#endif
    {
        ostream->write = (gtaio_stream_write_t)myio_ofilestream_write;
        ostream->finish = (gtaio_stream_finish_t)myio_ofilestream_finish;
        ostream->file = file;
        ret = true;
    }
    else {
        *p_errinfo = GTA_ERROR_INVALID_PARAMETER;
    }

    return ret;
}

/* gtaio_istream implementation to read from a temporary buffer */
size_t istream_from_buf_read
(
    istream_from_buf_t * istream,
    char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
)
{
    /* Check how many bytes are still available in data buffer */
    size_t bytes_available = istream->buf_size - istream->buf_pos;
    if (bytes_available < len) {
        /* Write only as many bytes as requested in case more are available */
        len = bytes_available;
    }

    /* Copy the bytes from the buffer */
    memcpy(data, &(istream->buf[istream->buf_pos]), len);
    /* Set new position in data buffer */
    istream->buf_pos += len;

    /* Return number of read bytes */
    return len;
}

bool istream_from_buf_eof
(
    istream_from_buf_t * istream,
    gta_errinfo_t * p_errinfo
)
{
    /* Return true if we are at the end of the buffer */
    return (istream->buf_pos == istream->buf_size);
}

void istream_from_buf_init
(
    istream_from_buf_t * istream,
    const char * buf,
    size_t buf_size
)
{
    istream->read = (gtaio_stream_read_t)istream_from_buf_read;
    istream->eof = (gtaio_stream_eof_t)istream_from_buf_eof;
    istream->buf = buf;
    istream->buf_size = buf_size;
    istream->buf_pos = 0;
}

bool ostream_finish(
    gtaio_ostream_t * ostream,
    gta_errinfo_t errinfo,
    gta_errinfo_t * p_errinfo
)
{
    return true;
}

/* gtaio_ostream implementation to write the output to a temporary buffer */
size_t ostream_to_buf_write
(
    ostream_to_buf_t * ostream,
    const char * data,
    size_t len,
    gta_errinfo_t * p_errinfo
)
{
    /* Check how many bytes are still available in data buffer */
    size_t bytes_available = ostream->buf_size - ostream->buf_pos;
    if (bytes_available < len) {
        /* Write only as many bytes as are still available in data buffer */
        len = bytes_available;
    }
    /* Copy the bytes to the buffer */
    memcpy(&(ostream->buf[ostream->buf_pos]), data, len);
    /* Set new position in data buffer */
    ostream->buf_pos += len;

    /* Return number of written bytes */
    return len;
}

void ostream_to_buf_init
(
    ostream_to_buf_t * ostream,
    char * buf,
    size_t buf_size
)
{
    ostream->write = (gtaio_stream_write_t)ostream_to_buf_write;
    ostream->finish = ostream_finish;
    ostream->buf = buf;
    ostream->buf_size = buf_size;
    ostream->buf_pos = 0;
}

/*** end of file ***/
