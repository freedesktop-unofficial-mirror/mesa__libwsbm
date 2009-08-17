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
 * Authors: Thomas Hellstrom <thomas-at-tungstengraphics-dot-com>
 */

#ifndef _WSBM_CS_H_
#define _WSBM_CS_H_
#include "wsbm_driver.h"

struct _WsbmFenceObject;
struct _WsbmBufferObject;
struct _ValidateList;

#define WSBM_PLACEMENT_MASK ((uint64_t) 0xFFFFFFFFULL)

extern struct _WsbmBufferList *wsbmBOCreateList(int target,
						int hasKernelBuffers,
						const struct _WsbmDriver *kernelDriver,
						const struct _WsbmDriver *userDriver);

extern int wsbmBOResetList(struct _WsbmBufferList *list);
extern int wsbmBOAddListItem(struct _WsbmBufferList *list,
			     struct _WsbmBufferObject *buf,
			     uint64_t flags, uint64_t mask, int *itemLoc,
			     struct _ValidateNode **node);

extern void wsbmBOFreeList(struct _WsbmBufferList *list);
extern int wsbmBOFenceUserList(struct _WsbmBufferList *list,
			       struct _WsbmFenceObject *fence);

extern int wsbmBOUnrefUserList(struct _WsbmBufferList *list);
extern int wsbmBOValidateUserList(struct _WsbmBufferList *list);
extern int wsbmBOUnvalidateUserList(struct _WsbmBufferList *list);

extern struct _ValidateList *wsbmGetKernelValidateList(struct _WsbmBufferList
						       *list);
extern struct _ValidateList *wsbmGetUserValidateList(struct _WsbmBufferList
						     *list);

extern struct _ValidateNode *validateListNode(void *iterator);
extern void *validateListIterator(struct _ValidateList *list);
extern void *validateListNext(struct _ValidateList *list, void *iterator);

#endif
