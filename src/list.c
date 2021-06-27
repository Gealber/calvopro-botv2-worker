#include "list.h"
#include "dbg.h"

List *List_create(void)
{
	return calloc(1, sizeof(List));
}

void List_destroy(List *list)
{
  LIST_FOREACH(list, first, next, cur) {
    if(cur->prev)
      free(cur->prev);
  }
  free(list->last);
  free(list);
}

void List_clear(List *list)
{
  if(!list->key_destroy)
    return ;
  LIST_FOREACH(list, first, next, cur) {
    list->key_destroy(cur->key);
  }
}

void List_clear_destroy(List *list)
{
  List_clear(list);
  List_destroy(list);
}

void List_push(List *list, void *key)
{
	ListNode *node = calloc(1, sizeof(ListNode));
	check_mem(node);

	node->key = key;
    if(list->last == NULL) {
      list->first = node;
      list->last = node;
    } else {
      list->last->next = node;
      node->prev = list->last;
      list->last = node;
    }
    list->count++;

error:
	return;
}

void *List_pop(List *list)
{
	ListNode *node = list->last;
	return node != NULL ? List_remove(list, node) : NULL;
}

void *List_remove(List *list, ListNode *node)
{
	void *result = NULL;

	check(list->first && list->last, "List is empty");
	check(node,"node can't be NULL");

	if(node == list->first && node == list->last) {
		list->first = NULL;
		list->last = NULL;
	} else if(node == list->first) {
		list->first = node->next;
		check(list->first != NULL, "Invalid list, somehow got a first that is NULL.");
		list->first->prev = NULL;
	} else {
		ListNode *after = node->next;
		ListNode *before = node->prev;
		after->prev = before;
		before->next = after;
	}

	list->count--;
	result = node->key;
	free(node);
error:
	return result;
}
