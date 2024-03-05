/** A list where pointers to nodes can be used to remove the node from the list.
 * Hence the list-infrastructure (nodes) are to some extent "open" to the user.
 * */
#ifndef __COMMON_OPEN_LIST_H
#define __COMMON_OPEN_LIST_H

#include <new>

/* Ownership of a node goes to the list on add_node. Each node may only be added
 * once (obviously because of the pointers / open architecture). On destruction,
 * no nodes are removed - hence the user MUST remove and free all nodes
 * manually.
 *
 * Usage example:
 *
 *   open_list<int> l;
 *
 *   open_list<int>::node n;
 *   n.elem = 10;
 *   l.add(n);     // Appends to end
 *   l.remove(n);
 *   l.remove(l.get_head());
 * */
template <typename T>
class open_list final
{
public:
	class node final
	{
		friend open_list;

	protected:
		node* prev = nullptr;
		node* next = nullptr;

	public:
		T elem;
	};

protected:
	node* head = nullptr;
	node* tail = nullptr;

public:
	node* get_head() noexcept
	{
		return head;
	}

	void add(node* n) noexcept
	{
		if (head)
		{
			n->prev = tail;
			n->next = nullptr;
			n->prev->next = n;

			tail = n;
		}
		else
		{
			n->prev = n->next = nullptr;
			head = tail = n;
		}
	}

	void remove(node* n) noexcept
	{
		if (n->prev)
			n->prev->next = n->next;

		if (n->next)
			n->next->prev = n->prev;

		if (head == n)
			head = n->next;

		if (tail == n)
			tail = n->prev;

		n->prev = nullptr;
		n->next = nullptr;
	}
};

#endif /* __COMMON_OPEN_LIST_H */
