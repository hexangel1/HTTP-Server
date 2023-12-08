#include <stdio.h>
#include <stdlib.h>
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

void free_buffer2(void *data)
{
        struct data_buffer *dbuf = data;
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

static void default_deleter(void *data)
{
        (void)data;
}

safe_value_t *make_safe_value(void *val, value_destructor del)
{
        struct safe_value *sv = malloc(sizeof(*sv));
        sv->value = val;
        sv->deleter = del ? del : &default_deleter;
        return sv;
}

void rewrite_safe_value(safe_value_t *sv, void *val, value_destructor del)
{
        if (sv->value)
                sv->deleter(sv->value);
        sv->value = val;
        sv->deleter = del ? del : &default_deleter;
}

void free_safe_value(safe_value_t *sv)
{
        if (!sv)
                return;
        if (sv->value)
                sv->deleter(sv->value);
        free(sv);
}

void *pick_safe_value(safe_value_t *sv)
{
        void *retval = sv->value;
        sv->value = NULL;
        sv->deleter = &default_deleter;
        return retval;
}

void *get_safe_value(safe_value_t *sv)
{
        return sv->value;
}
