#ifndef HASHMAP_H_SENTRY
#define HASHMAP_H_SENTRY

#include <stdlib.h>
#include <stdint.h>

#define HASHMAP_MISS ((uint64_t)-1)

struct hashmap {
        size_t size;
        size_t used;
        char **keys;
        uint64_t *vals;
};

struct hashmap *make_map(void);

void delete_map(struct hashmap *hm);

void hashmap_insert(struct hashmap *hm, const char *key, uint64_t val);

void hashmap_delete(struct hashmap *hm, const char *key);

uint64_t hashmap_search(struct hashmap *hm, const char *key);

void hashmap_foreach(struct hashmap *hm,
                     void (*cb)(const char *, uint64_t, void *), void *data);

#endif /* HASHMAP_H_SENTRY */

