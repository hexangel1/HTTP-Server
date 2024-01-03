#include <string.h>
#include "hashmap.h"

char *strdup(const char *str);

static const char DELETED;

static const size_t hashmap_sizes[] = {
        11,        /* > 8         */
        17,        /* > 16        */
        37,        /* > 32        */
        67,        /* > 64        */
        131,       /* > 128       */
        257,       /* > 256       */
        521,       /* > 512       */
        1031,      /* > 1024      */
        2053,      /* > 2048      */
        4099,      /* > 4096      */
        8209,      /* > 8192      */
        16411,     /* > 16384     */
        32771,     /* > 32768     */
        65537,     /* > 65536     */
        131101,    /* > 131072    */
        262147,    /* > 262144    */
        524309,    /* > 524288    */
        1048583,   /* > 1048576   */
        2097169,   /* > 2097152   */
        4194319,   /* > 4194304   */
        8388617,   /* > 8388608   */
        16777259,  /* > 16777216  */
        33554467,  /* > 33554432  */
        67108879,  /* > 67108864  */
        134217757, /* > 134217728 */
        0
};

static int is_key_valid(const char *key)
{
        return key && key != &DELETED;
}

static int keys_differ(const char *hmkey, const char *key)
{
        return hmkey == &DELETED || strcmp(hmkey, key);
}

static size_t get_hashmap_size(size_t cur_size)
{
        int i;
        for (i = 0; hashmap_sizes[i] && hashmap_sizes[i] <= cur_size; ++i)
                ;
        return hashmap_sizes[i];
}

static size_t hash_function(const char *key)
{
    const size_t hash_multiplier = 0x9c406bb5;
    const size_t hash_xor_op = 0x12fade34;

    register size_t hash_sum = 15;
    register int i = 0;

    while (*key) {
            hash_sum ^= (((size_t) *key) << (8 * (i % 4)));
            ++key; ++i;
    }
    return hash_multiplier * (hash_sum ^ hash_xor_op);
}

static void hashmap_evacuation(struct hashmap *hm)
{
        size_t idx, new_idx, new_used = 0;
        size_t new_size = get_hashmap_size(hm->size);

        char **new_keys = calloc(new_size, sizeof(char *));
        uint64_t *new_vals = malloc(new_size * sizeof(uint64_t));

        for (idx = 0; idx < hm->size; ++idx) {
                char *key = hm->keys[idx];
                if (!is_key_valid(key))
                        continue;
                new_idx = hash_function(key) % new_size;
                while (new_keys[new_idx])
                        new_idx = new_idx ? new_idx - 1 : new_size - 1;
                new_keys[new_idx] = key;
                new_vals[new_idx] = hm->vals[idx];
                new_used++;
        }
        free(hm->keys);
        free(hm->vals);
        hm->keys = new_keys;
        hm->vals = new_vals;
        hm->size = new_size;
        hm->used = new_used;
}

struct hashmap *make_map(void)
{
        struct hashmap *hm = malloc(sizeof(struct hashmap));
        size_t hash_size = get_hashmap_size(0);
        hm->size = hash_size;
        hm->used = 0;
        hm->keys = calloc(hash_size, sizeof(char *));
        hm->vals = malloc(hash_size * sizeof(uint64_t));
        return hm;
}

void delete_map(struct hashmap *hm)
{
        size_t idx;
        for (idx = 0; idx < hm->size; ++idx) {
                if (is_key_valid(hm->keys[idx]))
                        free(hm->keys[idx]);
        }
        free(hm->keys);
        free(hm->vals);
        free(hm);
}

void hashmap_insert(struct hashmap *hm, const char *key, uint64_t val)
{
        size_t idx = hash_function(key) % hm->size;

        while (is_key_valid(hm->keys[idx]) && strcmp(hm->keys[idx], key))
                idx = idx ? idx - 1 : hm->size - 1;

        if (!is_key_valid(hm->keys[idx]))
                hm->keys[idx] = strdup(key);
        hm->vals[idx] = val;
        hm->used++;

        if ((float)hm->used / (float)hm->size > 0.75f)
                hashmap_evacuation(hm);
}

void hashmap_delete(struct hashmap *hm, const char *key)
{
        size_t idx = hash_function(key) % hm->size;

        while (hm->keys[idx] && keys_differ(hm->keys[idx], key))
                idx = idx ? idx - 1 : hm->size - 1;

        if (!hm->keys[idx])
                return;
        free(hm->keys[idx]);
        hm->keys[idx] = (char *)&DELETED;
        hm->vals[idx] = HASHMAP_MISS;
}

uint64_t hashmap_search(struct hashmap *hm, const char *key)
{
        size_t idx = hash_function(key) % hm->size;

        while (hm->keys[idx] && keys_differ(hm->keys[idx], key))
                idx = idx ? idx - 1 : hm->size - 1;

        return hm->keys[idx] ? hm->vals[idx] : HASHMAP_MISS;
}

void hashmap_foreach(struct hashmap *hm,
                     void (*callback)(const char *, uint64_t, void *),
                     void *data)
{
        size_t idx;
        for (idx = 0; idx < hm->size; ++idx) {
                if (!is_key_valid(hm->keys[idx]))
                        continue;
                callback(hm->keys[idx], hm->vals[idx], data);
        }
}

