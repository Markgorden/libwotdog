#ifndef _G_LIST_H
#define _G_LIST_H
#ifdef __cplusplus
extern "C"{
#endif

struct list_head {
	struct list_head *next, *prev;
};

#if 1//ndef __cplusplus 

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

static inline void __list_add(struct list_head *newnode,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = newnode;
	newnode->next = next;
	newnode->prev = prev;
	prev->next = newnode;
}

static inline void list_add(struct list_head *newnode, struct list_head *head)
{
	__list_add(newnode, head, head->next);
}

static inline void list_add_tail(struct list_head *newnode, struct list_head *head)
{
	__list_add(newnode, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = (struct list_head *) 0;
	entry->prev = (struct list_head *) 0;
}

static inline void list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry); 
}

static inline void list_move(struct list_head *list, struct list_head *head)
{
	__list_del(list->prev, list->next);
    list_add(list, head);
}

static inline void list_move_tail(struct list_head *list,
				  struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add_tail(list, head);
}

static inline int list_empty(struct list_head *head)
{
	return head->next == head;
}

static inline void __list_splice(struct list_head *list,
				 struct list_head *head)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;
	struct list_head *at = head->next;

	first->prev = head;
	head->next = first;

	last->next = at;
	at->prev = last;
}

static inline void list_splice(struct list_head *list, struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head);
}

static inline void list_splice_init(struct list_head *list,
				    struct list_head *head)
{
	if (!list_empty(list)) {
		__list_splice(list, head);
		INIT_LIST_HEAD(list);
	}
}

#define list_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); \
        	pos = pos->next)
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); \
        	pos = pos->prev)
        	
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
		 &pos->member != (head); 					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#endif
#ifdef __cplusplus
}
#endif

#endif
