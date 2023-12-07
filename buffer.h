#ifndef BUFFER_H_SENTRY
#define BUFFER_H_SENTRY

#include <stdlib.h>

struct data_buffer {
        char *data;
        size_t buf_used;
        size_t buf_size;
};

struct data_buffer *make_buffer(size_t size);

void realloc_buffer(struct data_buffer *dbuf, size_t size);

void free_buffer(struct data_buffer *dbuf);

void write_buf_format(struct data_buffer *dbuf, const char *fmt, ...);

#endif
