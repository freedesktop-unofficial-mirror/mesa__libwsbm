/**************************************************************************
 *
 * Copyright 2006-2009 Vmware, Inc., Palo Alto, CA., USA
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 **************************************************************************/
/*
 * Authors: Thomas Hellstrom <thellstrom-at-vmware-dot-com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "wsbm_cs.h"
#include "wsbm_pool.h"

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

extern struct _WsbmBufStorage *
wsbmBOStorage(struct _WsbmBufferObject *buf);

struct _ValidateList
{
    const struct _WsbmVNodeDriver *driver;
    unsigned numTarget;
    unsigned numCurrent;
    unsigned numOnList;
    unsigned hashSize;
    uint32_t hashMask;
    struct _WsbmListHead list;
    struct _WsbmListHead free;
    struct _WsbmListHead *hashTable;
};

struct _WsbmBufferList
{
    int hasKernelBuffers;

    struct _ValidateList kernelBuffers;	/* List of kernel buffers needing validation */
    struct _ValidateList userBuffers;  /* List of user-space buffers needing validation */
};

static struct _ValidateNode *
validateListAddNode(struct _ValidateList *list, void *item,
		    uint32_t hash, uint64_t flags, uint64_t mask)
{
    struct _ValidateNode *node;
    struct _WsbmListHead *l;
    struct _WsbmListHead *hashHead;

    l = list->free.next;
    if (l == &list->free) {
	node = list->driver->alloc(list->driver);
	if (!node) {
	    return NULL;
	}
	list->numCurrent++;
    } else {
	WSBMLISTDEL(l);
	node = WSBMLISTENTRY(l, struct _ValidateNode, head);
    }
    node->buf = item;
    node->set_flags = flags & mask;
    node->clr_flags = (~flags) & mask;
    node->listItem = list->numOnList;
    WSBMLISTADDTAIL(&node->head, &list->list);
    list->numOnList++;
    hashHead = list->hashTable + hash;
    WSBMLISTADDTAIL(&node->hashHead, hashHead);

    return node;
}

static uint32_t
wsbmHashFunc(uint8_t * key, uint32_t len, uint32_t mask)
{
    uint32_t hash, i;

    for (hash = 0, i = 0; i < len; ++i) {
	hash += *key++;
	hash += (hash << 10);
	hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash & mask;
}

static void
validateFreeList(struct _ValidateList *list)
{
    struct _ValidateNode *node;
    struct _WsbmListHead *l;

    l = list->list.next;
    while (l != &list->list) {
	WSBMLISTDEL(l);
	node = WSBMLISTENTRY(l, struct _ValidateNode, head);

	WSBMLISTDEL(&node->hashHead);
	node->driver->free(node);
	l = list->list.next;
	list->numCurrent--;
	list->numOnList--;
    }

    l = list->free.next;
    while (l != &list->free) {
	WSBMLISTDEL(l);
	node = WSBMLISTENTRY(l, struct _ValidateNode, head);

	node->driver->free(node);
	l = list->free.next;
	list->numCurrent--;
    }
    free(list->hashTable);
}

static int
validateListAdjustNodes(struct _ValidateList *list)
{
    struct _ValidateNode *node;
    struct _WsbmListHead *l;
    int ret = 0;

    while (list->numCurrent < list->numTarget) {
	node = list->driver->alloc(list->driver);
	if (!node) {
	    ret = -ENOMEM;
	    break;
	}
	list->numCurrent++;
	WSBMLISTADD(&node->head, &list->free);
    }

    while (list->numCurrent > list->numTarget) {
	l = list->free.next;
	if (l == &list->free)
	    break;
	WSBMLISTDEL(l);
	node = WSBMLISTENTRY(l, struct _ValidateNode, head);

	node->driver->free(node);
	list->numCurrent--;
    }
    return ret;
}

static inline int
wsbmPot(unsigned int val)
{
    unsigned int shift = 0;
    while(val > (1 << shift))
	shift++;

    return shift;
}

static int
validateCreateList(int numTarget, struct _ValidateList *list,
		   const struct _WsbmVNodeDriver *driver)
{
    int i;
    unsigned int shift = wsbmPot(numTarget);
    int ret;

    list->hashSize = (1 << shift);
    list->hashMask = list->hashSize - 1;

    list->hashTable = malloc(list->hashSize * sizeof(*list->hashTable));
    if (!list->hashTable)
	return -ENOMEM;

    for (i = 0; i < list->hashSize; ++i)
	WSBMINITLISTHEAD(&list->hashTable[i]);

    WSBMINITLISTHEAD(&list->list);
    WSBMINITLISTHEAD(&list->free);
    list->numTarget = numTarget;
    list->numCurrent = 0;
    list->numOnList = 0;
    list->driver = driver;
    ret = validateListAdjustNodes(list);
    if (ret != 0)
	free(list->hashTable);

    return ret;
}

static int
validateResetList(struct _ValidateList *list)
{
    struct _WsbmListHead *l;
    struct _ValidateNode *node;
    int ret;

    ret = validateListAdjustNodes(list);
    if (ret)
	return ret;

    l = list->list.next;
    while (l != &list->list) {
	WSBMLISTDEL(l);
	node = WSBMLISTENTRY(l, struct _ValidateNode, head);

	WSBMLISTDEL(&node->hashHead);
	WSBMLISTADD(l, &list->free);
	list->numOnList--;
	l = list->list.next;
    }
    return validateListAdjustNodes(list);
}


/*
 * Note that lists are per-context and don't need mutex protection.
 */

struct _WsbmBufferList *
wsbmBOCreateList(int target, int hasKernelBuffers,
		 const struct _WsbmVNodeDriver *kernelDriver,
		 const struct _WsbmVNodeDriver *userDriver)
{
    struct _WsbmBufferList *list = calloc(sizeof(*list), 1);
    int ret;

    list->hasKernelBuffers = hasKernelBuffers;
    if (hasKernelBuffers) {
	ret = validateCreateList(target, &list->kernelBuffers, kernelDriver);
	if (ret)
	    return NULL;
    }

    ret = validateCreateList(target, &list->userBuffers, userDriver);
    if (ret) {
	validateFreeList(&list->kernelBuffers);
	return NULL;
    }

    return list;
}

int
wsbmBOResetList(struct _WsbmBufferList *list)
{
    int ret;

    if (list->hasKernelBuffers) {
	ret = validateResetList(&list->kernelBuffers);
	if (ret)
	    return ret;
    }
    ret = validateResetList(&list->userBuffers);
    return ret;
}

void
wsbmBOFreeList(struct _WsbmBufferList *list)
{
    if (list->hasKernelBuffers)
	validateFreeList(&list->kernelBuffers);
    validateFreeList(&list->userBuffers);
    free(list);
}

static int
wsbmAddValidateItem(struct _ValidateList *list, void *buf, uint64_t flags,
		    uint64_t mask, int *itemLoc,
		    struct _ValidateNode **pnode, int *newItem)
{
    struct _ValidateNode *node, *cur;
    struct _WsbmListHead *l;
    struct _WsbmListHead *hashHead;
    uint32_t hash;
    uint32_t count = 0;
    uint32_t key = (unsigned long) buf;

    cur = NULL;
    hash = wsbmHashFunc((uint8_t *) &key, 4, list->hashMask);
    hashHead = list->hashTable + hash;
    *newItem = 0;

    for (l = hashHead->next; l != hashHead; l = l->next) {
        count++;
	node = WSBMLISTENTRY(l, struct _ValidateNode, hashHead);

	if (node->buf == buf) {
	    cur = node;
	    break;
	}
    }

    if (!cur) {
	int ret;

	cur = validateListAddNode(list, buf, hash, flags, mask);
	if (!cur)
	    return -ENOMEM;

	ret = cur->driver->init(cur);
	if (ret != 0) {
	    WSBMLISTDEL(&cur->head);
	    WSBMLISTDEL(&cur->hashHead);
	    list->numOnList--;
	    WSBMLISTADD(&cur->head, &list->free);
	    return ret;
	}

	*newItem = 1;
    } else {
	uint64_t set_flags = flags & mask;
	uint64_t clr_flags = (~flags) & mask;

	if (((cur->clr_flags | clr_flags) & WSBM_PLACEMENT_MASK) ==
	    WSBM_PLACEMENT_MASK) {
	    /*
	     * No available memory type left. Bail.
	     */
	    return -EINVAL;
	}

	if ((cur->set_flags | set_flags) &
	    (cur->clr_flags | clr_flags) & ~WSBM_PLACEMENT_MASK) {
	    /*
	     * Conflicting flags. Bail.
	     */
	    return -EINVAL;
	}

	set_flags |= cur->set_flags;
	clr_flags |= cur->clr_flags;
	set_flags &= ~clr_flags;

	if (cur->driver->reaccount && (set_flags != cur->set_flags)) {
	    int ret = cur->driver->reaccount(cur, set_flags, clr_flags);
	    if (ret)
		return ret;
	}

	cur->set_flags = set_flags;
	cur->clr_flags = clr_flags;
    }
    *itemLoc = cur->listItem;
    if (pnode)
	*pnode = cur;
    return 0;
}


int
wsbmBOAddListItem(struct _WsbmBufferList *list,
		  struct _WsbmBufferObject *buf,
		  uint64_t flags, uint64_t mask, int *itemLoc,
		  struct _ValidateNode **node)
{
    int newItem;
    struct _WsbmBufStorage *storage = wsbmBOStorage(buf);
    int ret;
    int dummy;
    struct _ValidateNode *dummyNode;

    if (list->hasKernelBuffers) {
	ret = wsbmAddValidateItem(&list->kernelBuffers,
				  storage->pool->kernel(storage),
				  flags, mask, itemLoc, node, &dummy);
	if (ret)
	    goto out_unlock;
    } else {
	*node = NULL;
	*itemLoc = -1000;
    }

    ret = wsbmAddValidateItem(&list->userBuffers, storage,
			      flags, mask, &dummy, &dummyNode, &newItem);
    if (ret)
	goto out_unlock;

    if (newItem) {
	wsbmAtomicInc(&storage->refCount);
	wsbmAtomicInc(&storage->onList);
    }

  out_unlock:
    return ret;
}

int
wsbmBOUnrefUserList(struct _WsbmBufferList *list)
{
    struct _WsbmBufStorage *storage;
    void *curBuf;

    curBuf = validateListIterator(&list->userBuffers);

    while (curBuf) {
	storage = (struct _WsbmBufStorage *)(validateListNode(curBuf)->buf);
	wsbmAtomicDec(&storage->onList);
	wsbmBufStorageUnref(&storage);
	curBuf = validateListNext(&list->userBuffers, curBuf);
    }

    return wsbmBOResetList(list);
}


int
wsbmBOFenceUserList(struct _WsbmBufferList *list,
		    struct _WsbmFenceObject *fence)
{
    struct _WsbmBufStorage *storage;
    void *curBuf;

    curBuf = validateListIterator(&list->userBuffers);

    /*
     * User-space fencing callbacks.
     */

    while (curBuf) {
	storage = (struct _WsbmBufStorage *)(validateListNode(curBuf)->buf);

	storage->pool->fence(storage, fence);
	wsbmAtomicDec(&storage->onList);
	wsbmBufStorageUnref(&storage);
	curBuf = validateListNext(&list->userBuffers, curBuf);
    }

    return wsbmBOResetList(list);
}

int
wsbmBOValidateUserList(struct _WsbmBufferList *list)
{
    void *curBuf;
    struct _WsbmBufStorage *storage;
    struct _ValidateNode *node;
    int ret;

    curBuf = validateListIterator(&list->userBuffers);

    /*
     * User-space validation callbacks.
     */

    while (curBuf) {
	node = validateListNode(curBuf);
	storage = (struct _WsbmBufStorage *)node->buf;
	if (storage->pool->validate) {
	    ret = storage->pool->validate(storage, node->set_flags,
					  node->clr_flags);
	    if (ret)
		return ret;
	}
	curBuf = validateListNext(&list->userBuffers, curBuf);
    }
    return 0;
}

int wsbmBOUnvalidateUserList(struct _WsbmBufferList *list)
{
    void *curBuf;
    struct _WsbmBufStorage *storage;
    struct _ValidateNode *node;

    curBuf = validateListIterator(&list->userBuffers);

    /*
     * User-space validation callbacks.
     */

    while (curBuf) {
	node = validateListNode(curBuf);
	storage = (struct _WsbmBufStorage *)node->buf;
	if (storage->pool->unvalidate) {
	    storage->pool->unvalidate(storage);
	}
	wsbmAtomicDec(&storage->onList);
	wsbmBufStorageUnref(&storage);
	curBuf = validateListNext(&list->userBuffers, curBuf);
    }
    return wsbmBOResetList(list);
}

struct _ValidateList *
wsbmGetKernelValidateList(struct _WsbmBufferList *list)
{
    return (list->hasKernelBuffers) ? &list->kernelBuffers : NULL;
}

struct _ValidateList *
wsbmGetUserValidateList(struct _WsbmBufferList *list)
{
    return &list->userBuffers;
}

struct _ValidateNode *
validateListNode(void *iterator)
{
    struct _WsbmListHead *l = (struct _WsbmListHead *)iterator;

    return WSBMLISTENTRY(l, struct _ValidateNode, head);
}

void *
validateListIterator(struct _ValidateList *list)
{
    void *ret = list->list.next;

    if (ret == &list->list)
	return NULL;
    return ret;
}

void *
validateListNext(struct _ValidateList *list, void *iterator)
{
    void *ret;

    struct _WsbmListHead *l = (struct _WsbmListHead *)iterator;

    ret = l->next;
    if (ret == &list->list)
	return NULL;
    return ret;
}
