#include <stdio.h>
#include <stdarg.h>
#include "buffer.h"

struct data_buffer *make_buffer(size_t size)
{
        struct data_buffer *dbuf = malloc(sizeof(*dbuf));
        dbuf->data = malloc(size);
        dbuf->buf_size = size;
        dbuf->buf_used = 0;
        return dbuf;
}

void free_buffer(struct data_buffer *dbuf)
{
        free(dbuf->data);
        free(dbuf);
}

void write_buf_format(struct data_buffer *dbuf, const char *fmt, ...)
{
        va_list vl;
        va_start(vl, fmt);
        dbuf->buf_used += vsnprintf(dbuf->data + dbuf->buf_used,
                                    dbuf->buf_size - dbuf->buf_used, fmt, vl);
        va_end(vl);
}