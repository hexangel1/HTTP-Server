#ifndef ARRAY_H_SENTRY
#define ARRAY_H_SENTRY

#include <stdlib.h>

#define DECLARE_ARRAY_OF(array_type, elem_type) \
typedef struct interal_ ## array_type { \
        size_t size; \
        size_t used; \
        elem_type *data; \
} array_type

#define ARRAY_INIT(arr, init_size) \
do { \
        (arr)->size = (init_size); \
        (arr)->used = 0; \
        if ((init_size) > 0) \
            (arr)->data = malloc((arr)->size * sizeof(*(arr)->data)); \
        else \
            (arr)->data = NULL; \
} while (0)

#define ARRAY_LEN(arr) ((arr)->used)

#define ARRAY_SIZE(arr) ((arr)->size)

#define ARRAY_GET(arr, i) ((arr)->data[(i)])

#define ARRAY_APPEND(arr, value) \
do { \
        if ((arr)->used == (arr)->size) { \
                (arr)->size = (arr)->size ? (arr)->size << 1 : 8; \
                (arr)->data = realloc((arr)->data, \
                        (arr)->size * sizeof(*(arr)->data)); \
        } \
        (arr)->data[(arr)->used] = (value); \
        (arr)->used++; \
} while (0)

#define ARRAY_FOREACH(arr, callback) \
do { \
        size_t i; \
        for (i = 0; i < (arr)->used; ++i) \
                callback((arr)->data[i]); \
} while (0)

#define ARRAY_FREE(arr) free((arr)->data)

#define ARRAY_FREE2(arr, deleter) \
do { \
        ARRAY_FOREACH(arr, deleter); \
        ARRAY_FREE(arr); \
} while (0)

#endif
