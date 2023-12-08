#ifndef BUFFER_H_SENTRY
#define BUFFER_H_SENTRY

#include <stdlib.h>

struct data_buffer {
        char *data;
        size_t buf_used;
        size_t buf_size;
};

typedef void (*value_destructor)(void *);

typedef struct safe_value {
        void *value;
        value_destructor deleter;
} safe_value_t;

struct data_buffer *make_buffer(size_t size);

void free_buffer(struct data_buffer *dbuf);

void free_buffer2(void *data);

void write_buf_format(struct data_buffer *dbuf, const char *fmt, ...);

safe_value_t *make_safe_value(void *val, value_destructor del);

void rewrite_safe_value(safe_value_t *sv, void *val, value_destructor del);

void free_safe_value(safe_value_t *sv);

void *get_safe_value(safe_value_t *sv);

void *pick_safe_value(safe_value_t *sv);

#endif
