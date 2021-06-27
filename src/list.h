#ifndef _LIST_H
#define _LIST_H
#include <stdlib.h>

/*
 * L.head -> ... prev|key|next ... <- L.tail*/
struct ListNode;

typedef void (*Key_destroy)(void *key);

typedef struct ListNode {
  struct ListNode *prev;
  struct ListNode *next;
  void *key;
}ListNode;

typedef struct List {
  int count;
  ListNode *first; /*points to the first element*/
  ListNode *last; /*points to the last element*/
  Key_destroy key_destroy; /*function to destroy a key*/
} List;

List *List_create(void);
/*not going to need search, 
 * so I'm ommiting on purpose*/


/*insert node with given key*/
void List_push(List *list, void *key);

/*we are not going to use this one by now*/
void *List_pop(List *list);

/*destroy the linked list*/
void List_destroy(List *list);
void List_clear(List *list);
void List_clear_destroy(List *list);

void *List_remove(List *list, ListNode *node);

/*useful macro from LCTHW(Learn C the hard way)*/
#define LIST_FOREACH(L, S, M, V) ListNode *_node = NULL;\
    ListNode *V = NULL;\
    for(V = _node = L->S; _node != NULL; V = _node = _node->M)

#endif
