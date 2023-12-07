#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tree.h"

static int balance_factor(struct tree_node *root)
{
        return tree_height(root->right) - tree_height(root->left);
}

static void update_height(struct tree_node *root)
{
        unsigned int lh, rh;
        lh = tree_height(root->left);
        rh = tree_height(root->right);
        root->height = (lh > rh ? lh : rh) + 1;
}

static void free_tree_node(struct tree_node *root)
{
        free(root->key);
        free(root);
}

static struct tree_node *rotate_right(struct tree_node *root)
{
        struct tree_node *new_root;
        new_root = root->left;
        new_root->parent = root->parent;
        root->left = new_root->right;
        if (new_root->right)
                new_root->right->parent = new_root;
        new_root->right = root;
        root->parent = new_root;
        update_height(root);
        update_height(new_root);
        return new_root;
}

static struct tree_node *rotate_left(struct tree_node *root)
{
        struct tree_node *new_root;
        new_root = root->right;
        new_root->parent = root->parent;
        root->right = new_root->left;
        if (new_root->left)
                new_root->left->parent = new_root;
        new_root->left = root;
        root->parent = new_root;
        update_height(root);
        update_height(new_root); 
        return new_root;
}

static struct tree_node *tree_balance(struct tree_node *root)
{
        update_height(root);
        if (balance_factor(root) == 2) {
                if (balance_factor(root->right) < 0)
                        root->right = rotate_right(root->right);
                return rotate_left(root);
        }
        if (balance_factor(root) == -2) {
                if (balance_factor(root->left) > 0)
                        root->left = rotate_left(root->left);
                return rotate_right(root);
        }
        return root;
}

static struct tree_node *_tree_unset(struct tree_node *root, const char *key);

static struct tree_node *tree_delete(struct tree_node *root)
{
        struct tree_node *ret, *q;
        if (!root->left && !root->right) {
                free_tree_node(root);
                ret = NULL;
        } else if (!root->left || !root->right) {
                q = root->right ? root->right : root->left;
                q->parent = root->parent;
                free_tree_node(root);
                ret = q;
        } else {
                q = tree_min(root->right);
                free(root->key);
                root->key = strdup(q->key);
                root->value = q->value;
                root->right = _tree_unset(root->right, q->key);
                ret = tree_balance(root);
        }
        return ret;
}

static struct tree_node *_tree_set(struct tree_node *root, struct tree_node *p,
                                   const char *key, unsigned int val)
{
        int res;
        if (!root) {
                root = malloc(sizeof(*root));
                root->key = strdup(key);
                root->value = val;
                root->height = 1;
                root->left = NULL;
                root->right = NULL;
                root->parent = p;
        } else {
                res = strcmp(key, root->key);
                if (res == 0)
                        root->value = val;
                else if (res > 0)
                        root->right = _tree_set(root->right, root, key, val);
                else
                        root->left = _tree_set(root->left, root, key, val);
        }
        return tree_balance(root);
}

static struct tree_node *_tree_unset(struct tree_node *root, const char *key)
{
        int res;
        if (!root)
                return NULL;
        res = strcmp(key, root->key);
        if (res == 0) 
                return tree_delete(root);
        if (res > 0)
                root->right = _tree_unset(root->right, key);
        else
                root->left = _tree_unset(root->left, key);
        return tree_balance(root);
}

static struct tree_node *_tree_get(struct tree_node *root, const char *key)
{
        int res;
        res = root ? strcmp(key, root->key) : 0;
        if (!res)
                return root;
        return _tree_get(res > 0 ? root->right : root->left, key);
}

void tree_set(struct tree_node **root, const char *key, unsigned int val)
{
        *root = _tree_set(*root, NULL, key, val);
}

void tree_unset(struct tree_node **root, const char *key)
{
        *root = _tree_unset(*root, key);
}

unsigned int tree_get(struct tree_node *root, const char *key)
{
        struct tree_node *node = _tree_get(root, key);
        return node ? node->value : (unsigned int)-1;
}

void tree_free(struct tree_node *root)
{
        if (root) {
                tree_free(root->left);
                tree_free(root->right);
                free_tree_node(root);
        }
}

void tree_print(struct tree_node *root)
{
        if (root) {
                tree_print(root->left);
                fprintf(stderr, "%s -> %i\n", root->key, root->value);
                tree_print(root->right);
        }
}

void tree_check(struct tree_node *root)
{
        if (root) {
                tree_check(root->left);
                if (abs(balance_factor(root)) > 1)
                        fprintf(stderr, "Not balanced node!\n");
                tree_check(root->right);
        }
}

unsigned int tree_size(struct tree_node *root)
{
        return root ? tree_size(root->left) + tree_size(root->right) + 1 : 0;
}

unsigned int tree_height(struct tree_node *root)
{
        return root ? root->height : 0;
}

struct tree_node *tree_max(struct tree_node *root)
{
        return root->right ? tree_max(root->right) : root;
}

struct tree_node *tree_min(struct tree_node *root)
{
        return root->left ? tree_min(root->left) : root;
}

