#ifndef TREE_H_SENTRY
#define TREE_H_SENTRY

struct tree_node {
        char *key;
        unsigned int value;
        unsigned int height;
        struct tree_node *left;
        struct tree_node *right;
        struct tree_node *parent;
};

/* inserts new elem */
void tree_set(struct tree_node **root, const char *key, unsigned int val);

/* delete elem */
void tree_unset(struct tree_node **root, const char *key);

/* gets elem */
unsigned int tree_get(struct tree_node *root, const char *key);

/* frees tree */
void tree_free(struct tree_node *root);

/* prints tree */
void tree_print(struct tree_node *root);

/* checks tree balance */
void tree_check(struct tree_node *root);

/* return tree size */
unsigned int tree_size(struct tree_node *root);

/* return tree height */
unsigned int tree_height(struct tree_node *root);

/* return max elem */
struct tree_node *tree_max(struct tree_node *root);

/* return min elem */
struct tree_node *tree_min(struct tree_node *root);

#endif /* TREE_H_SENTRY */

