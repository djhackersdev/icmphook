#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "icmphook/list.h"

void list_init(struct list *list)
{
    memset(list, 0, sizeof(*list));
}

void list_append(struct list *list, struct list_node *node)
{
    assert(list != NULL);
    assert(node != NULL);

    node->next = NULL;

    if (list->tail != NULL) {
        list->tail->next = node;
    } else {
        list->head = node;
    }

    list->tail = node;
}

struct list_node *list_pop_head(struct list *list)
{
    struct list_node *node;

    assert(list != NULL);

    if (list->head == NULL) {
        return NULL;
    }

    node = list->head;
    list->head = node->next;

    if (node->next == NULL) {
        list->tail = NULL;
    }

    node->next = NULL;

    return node;
}

void list_unlink(
        struct list *list,
        struct list_node *node,
        struct list_node *prev)
{
    assert(list != NULL);
    assert(node != NULL);

    if (prev != NULL) {
        prev->next = node->next;
    } else {
        list->head = node->next;
    }

    if (node->next == NULL) {
        list->tail = prev;
    }

    node->next = NULL;
}
