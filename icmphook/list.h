#pragma once

#include <stdbool.h>
#include <stddef.h>

struct list {
    struct list_node *head;
    struct list_node *tail;
};

struct list_node {
    struct list_node *next;
};

void list_init(struct list *list);
void list_append(struct list *list, struct list_node *node);
struct list_node *list_pop_head(struct list *list);
void list_unlink(
        struct list *list,
        struct list_node *node,
        struct list_node *prev);
