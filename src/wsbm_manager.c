/**************************************************************************
 *
 * Copyright 2006-2008 Tungsten Graphics, Inc., Cedar Park, TX., USA
 * All Rights Reserved.
 * Copyright 2009 Vmware, Inc., Palo Alto, CA., USA
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
 * Authors: Thomas Hellström <thomas-at-tungstengraphics-dot-com>
 *          Keith Whitwell <keithw-at-tungstengraphics-dot-com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "errno.h"
#include "string.h"
#include "wsbm_pool.h"
#include "wsbm_manager.h"
#include "wsbm_fencemgr.h"
#include "wsbm_driver.h"
#include "wsbm_priv.h"
#include "wsbm_util.h"
#include "wsbm_atomic.h"
#include "assert.h"

#define WSBM_BODATA_SIZE_ACCEPT 4096

#define WSBM_BUFFER_COMPLEX 0
#define WSBM_BUFFER_SIMPLE  1
#define WSBM_BUFFER_REF     2

struct _WsbmBufferObject
{
    /* Left to the client to protect this data for now. */

    struct _WsbmAtomic refCount;
    struct _WsbmBufStorage *storage;
    struct _WsbmAttr attr;
    struct _WsbmBufferPool *pool;
    unsigned bufferType;
    int hasAttr;
};

static int initialized = 0;
static struct _WsbmCommon *commonData = NULL;

int
wsbmInit(struct _WsbmThreadFuncs *tf)
{
    wsbmCurThreadFunc = tf;
    initialized = 1;
    return 0;
}

void
wsbmCommonDataSet(struct _WsbmCommon *common)
{
    commonData = common;
}

struct _WsbmCommon *
wsbmCommonDataGet(void)
{
    if (commonData == NULL)
	return NULL;
    ++commonData->refCount;
    return commonData;
}

void
wsbmCommonDataPut(void)
{
    if (commonData == NULL)
	abort();

    if (--commonData->refCount == 0) {
	commonData->destroy(commonData);
	commonData = NULL;
    }
}

int
wsbmIsInitialized(void)
{
    return initialized;
}

void
wsbmTakedown(void)
{
    initialized = 0;
    commonData = NULL;
}

void
wsbmBOWaitIdle(struct _WsbmBufferObject *buf, int lazy)
{
    struct _WsbmBufStorage *storage;

    storage = buf->storage;
    if (!storage)
	return;

    (void)storage->pool->waitIdle(storage, lazy);
}

void *
wsbmBOMap(struct _WsbmBufferObject *buf, unsigned mode)
{
    struct _WsbmBufStorage *storage = buf->storage;
    void *virtual;
    int retval;

    retval = storage->pool->map(storage, mode, &virtual);

    return (retval == 0) ? virtual : NULL;
}

void
wsbmBOUnmap(struct _WsbmBufferObject *buf)
{
    struct _WsbmBufStorage *storage = buf->storage;

    storage->pool->unmap(storage);
}

int
wsbmBOSyncForCpu(struct _WsbmBufferObject *buf, unsigned mode,
		 int noBlock)
{
    struct _WsbmBufStorage *storage = buf->storage;

    return storage->pool->syncforcpu(storage, mode, noBlock);
}

void
wsbmBOReleaseFromCpu(struct _WsbmBufferObject *buf, unsigned mode)
{
    struct _WsbmBufStorage *storage = buf->storage;

    storage->pool->releasefromcpu(storage, mode);
}

unsigned long
wsbmBOOffsetHint(struct _WsbmBufferObject *buf)
{
    struct _WsbmBufStorage *storage = buf->storage;

    return storage->pool->offset(storage);
}

unsigned long
wsbmBOPoolOffset(struct _WsbmBufferObject *buf)
{
    struct _WsbmBufStorage *storage = buf->storage;

    return storage->pool->poolOffset(storage);
}

uint32_t
wsbmBOPlacementHint(struct _WsbmBufferObject * buf)
{
    struct _WsbmBufStorage *storage = buf->storage;

    assert(buf->storage != NULL);

    return storage->pool->placement(storage);
}

struct _WsbmBufferObject *
wsbmBOReference(struct _WsbmBufferObject *buf)
{
    if (buf->bufferType == WSBM_BUFFER_SIMPLE) {
	wsbmAtomicInc(&buf->storage->refCount);
    } else {
	wsbmAtomicInc(&buf->refCount);
    }
    return buf;
}

int
wsbmBOSetAttr(struct _WsbmBufferObject *buf,
	      const struct _WsbmAttr *attr)
{
    struct _WsbmBufStorage *storage = buf->storage;

    if (!storage)
	return 0;

    if (storage->pool->setAttr == NULL)
	return -EINVAL;

    buf->attr = *attr;
    return storage->pool->setAttr(storage,
				  attr->setPlacement,
				  attr->alignment,
				  attr->share,
				  attr->pin);
}

void
wsbmBOUnreference(struct _WsbmBufferObject **p_buf)
{
    struct _WsbmBufferObject *buf = *p_buf;

    *p_buf = NULL;

    if (!buf)
	return;

    if (buf->bufferType == WSBM_BUFFER_SIMPLE) {
	struct _WsbmBufStorage *dummy = buf->storage;

	wsbmBufStorageUnref(&dummy);
	return;
    }

    if (wsbmAtomicDecZero(&buf->refCount)) {
	wsbmBufStorageUnref(&buf->storage);
	free(buf);
    }
}

static inline int
wsbmAttrDiff(const struct _WsbmAttr *attr1,
	     const struct _WsbmAttr *attr2)
{
    return (attr1->setPlacement != attr2->setPlacement) ||
	(attr1->clrPlacement != attr2->clrPlacement) ||
	(attr1->alignment != attr2->alignment) ||
	(attr1->share != attr2->share) ||
	(attr1->pin != attr2->pin);
}

int
wsbmBOData(struct _WsbmBufferObject *buf,
	   unsigned size, const void *data,
	   struct _WsbmBufferPool *newPool,
	   const struct _WsbmAttr *attr)
{
    void *virtual = NULL;
    int newBuffer;
    int retval = 0;
    struct _WsbmBufStorage *storage;
    int synced = 0;
    struct _WsbmBufferPool *curPool;
    const struct _WsbmAttr *tmpAttr = attr;

    if (buf->bufferType == WSBM_BUFFER_SIMPLE)
	return -EINVAL;

    storage = buf->storage;

    if (newPool == NULL)
	newPool = buf->pool;

    if (newPool == NULL)
	return -EINVAL;

    newBuffer = (!storage || storage->pool != newPool ||
		 storage->pool->size(storage) < size ||
		 storage->pool->size(storage) >
		 size + WSBM_BODATA_SIZE_ACCEPT);

    if (!tmpAttr) {
	if (buf->hasAttr)
	    tmpAttr = &buf->attr;
	else
	    return -EINVAL;
    }

    if (newBuffer) {
	if (buf->bufferType == WSBM_BUFFER_REF)
	    return -EINVAL;

	wsbmBufStorageUnref(&buf->storage);

	if (size == 0) {
	    buf->pool = newPool;
	    buf->attr = *tmpAttr;
	    buf->hasAttr = 1;
	    retval = 0;
	    goto out;
	}

	buf->storage =
	    newPool->create(newPool, size, tmpAttr->setPlacement,
			    tmpAttr->alignment,
			    tmpAttr->share,
			    tmpAttr->pin);
	if (!buf->storage) {
	    retval = -ENOMEM;
	    goto out;
	}

	buf->attr = *tmpAttr;
	buf->hasAttr = 1;
	buf->pool = newPool;
    } else if (wsbmAtomicRead(&storage->onList) ||
	       0 != storage->pool->syncforcpu(storage, WSBM_SYNCCPU_WRITE, 1)) {
	/*
	 * Buffer is busy. need to create a new one.
	 */

	struct _WsbmBufStorage *tmp_storage;

	curPool = storage->pool;

	tmp_storage =
	    curPool->create(curPool, size, tmpAttr->setPlacement,
			    tmpAttr->alignment,
			    tmpAttr->share,
			    tmpAttr->pin);

	if (tmp_storage) {
	    wsbmBufStorageUnref(&buf->storage);
	    buf->storage = tmp_storage;
	    buf->attr = *tmpAttr;
	} else {
	    retval = curPool->syncforcpu(storage, WSBM_SYNCCPU_WRITE, 0);
	    if (retval)
		goto out;
	    synced = 1;
	}
    } else
	synced = 1;

    /*
     * We might need to change buffer placement.
     */

    storage = buf->storage;
    curPool = storage->pool;

    if (wsbmAttrDiff(&buf->attr, tmpAttr)) {
	assert(curPool->setAttr != NULL);
	if (synced) {
	    curPool->releasefromcpu(storage, WSBM_SYNCCPU_WRITE);
	    synced = 0;
	}
	retval = curPool->setAttr(storage,
				  tmpAttr->setPlacement,
				  tmpAttr->alignment,
				  tmpAttr->share,
				  tmpAttr->pin);
	if (retval)
	    goto out;
	buf->attr = *tmpAttr;
    }

    if (!synced && data) {
	retval = curPool->syncforcpu(buf->storage, WSBM_SYNCCPU_WRITE, 0);

	if (retval)
	    goto out;
	synced = 1;
    }

    storage = buf->storage;
    curPool = storage->pool;

    if (data) {
	retval = curPool->map(storage, WSBM_ACCESS_WRITE, &virtual);
	if (retval)
	    goto out;
	memcpy(virtual, data, size);
	curPool->unmap(storage);
    }

  out:

    if (synced)
	curPool->releasefromcpu(storage, WSBM_SYNCCPU_WRITE);

    return retval;
}

static struct _WsbmBufStorage *
wsbmStorageClone(struct _WsbmBufferObject *buf)
{
    struct _WsbmBufStorage *storage = buf->storage;
    struct _WsbmBufferPool *pool = storage->pool;
    struct _WsbmAttr *attr = &buf->attr;

    return pool->create(pool, pool->size(storage),
			attr->setPlacement,
			attr->alignment,
			attr->share,
			attr->pin);
}

struct _WsbmBufferObject *
wsbmBOClone(struct _WsbmBufferObject *buf,
	    int (*accelCopy) (struct _WsbmBufferObject *,
			      struct _WsbmBufferObject *))
{
    struct _WsbmBufferObject *newBuf;
    int ret;

    newBuf = malloc(sizeof(*newBuf));
    if (!newBuf)
	return NULL;

    *newBuf = *buf;
    newBuf->storage = wsbmStorageClone(buf);
    if (!newBuf->storage)
	goto out_err0;

    wsbmAtomicSet(&newBuf->refCount, 1);
    if (!accelCopy || accelCopy(newBuf, buf) != 0) {

	struct _WsbmBufferPool *pool = buf->storage->pool;
	struct _WsbmBufStorage *storage = buf->storage;
	struct _WsbmBufStorage *newStorage = newBuf->storage;
	void *virtual;
	void *nVirtual;

	ret = pool->syncforcpu(storage, WSBM_SYNCCPU_READ, 0);
	if (ret)
	    goto out_err1;
	ret = pool->map(storage, WSBM_ACCESS_READ, &virtual);
	if (ret)
	    goto out_err2;
	ret = pool->map(newStorage, WSBM_ACCESS_WRITE, &nVirtual);
	if (ret)
	    goto out_err3;

	memcpy(nVirtual, virtual, pool->size(storage));
	pool->unmap(newBuf->storage);
	pool->unmap(buf->storage);
	pool->releasefromcpu(storage, WSBM_SYNCCPU_READ);
    }

    return newBuf;
  out_err3:
    buf->pool->unmap(buf->storage);
  out_err2:
    buf->pool->releasefromcpu(buf->storage, WSBM_SYNCCPU_READ);
  out_err1:
    wsbmBufStorageUnref(&newBuf->storage);
  out_err0:
    free(newBuf);
    return 0;
}

int
wsbmBOSubData(struct _WsbmBufferObject *buf,
	      unsigned long offset, unsigned long size, const void *data,
	      int (*accelCopy) (struct _WsbmBufferObject *,
				struct _WsbmBufferObject *))
{
    int ret = 0;

    if (buf->bufferType == WSBM_BUFFER_SIMPLE)
	return -EINVAL;

    if (size && data) {
	void *virtual;
	struct _WsbmBufStorage *storage = buf->storage;
	struct _WsbmBufferPool *pool = storage->pool;

	ret = pool->syncforcpu(storage, WSBM_SYNCCPU_WRITE, 0);
	if (ret)
	    goto out;

	if (wsbmAtomicRead(&storage->onList)) {

	    struct _WsbmBufferObject *newBuf;

	    /*
	     * Another context has this buffer on its validate list.
	     * This should be a very rare situation, but it can be valid,
	     * and therefore we must deal with it by cloning the storage.
	     */

	    pool->releasefromcpu(storage, WSBM_SYNCCPU_WRITE);
	    newBuf = wsbmBOClone(buf, accelCopy);

	    /*
	     * If clone fails we have the choice of either bailing.
	     * (The other context will be happy), or go on and update
	     * the old buffer anyway. (We will be happy). We choose the
	     * latter.
	     */

	    if (newBuf) {
		storage = newBuf->storage;
		wsbmAtomicInc(&storage->refCount);
		wsbmBufStorageUnref(&buf->storage);
		buf->storage = storage;
		wsbmBOUnreference(&newBuf);
		pool = storage->pool;
	    }

	    ret = pool->syncforcpu(storage, WSBM_SYNCCPU_WRITE, 0);
	    if (ret)
		goto out;
	}

	ret = pool->map(storage, WSBM_ACCESS_WRITE, &virtual);
	if (ret) {
	    pool->releasefromcpu(storage, WSBM_SYNCCPU_WRITE);
	    goto out;
	}

	memcpy((unsigned char *)virtual + offset, data, size);
	pool->unmap(storage);
	pool->releasefromcpu(storage, WSBM_SYNCCPU_WRITE);
    }
  out:
    return ret;
}

int
wsbmBOGetSubData(struct _WsbmBufferObject *buf,
		 unsigned long offset, unsigned long size, void *data)
{
    int ret = 0;

    if (size && data) {
	void *virtual;
	struct _WsbmBufStorage *storage = buf->storage;
	struct _WsbmBufferPool *pool = storage->pool;

	ret = pool->syncforcpu(storage, WSBM_SYNCCPU_READ, 0);
	if (ret)
	    goto out;
	ret = pool->map(storage, WSBM_ACCESS_READ, &virtual);
	if (ret) {
	    pool->releasefromcpu(storage, WSBM_SYNCCPU_WRITE);
	    goto out;
	}
	memcpy(data, (unsigned char *)virtual + offset, size);
	pool->unmap(storage);
	pool->releasefromcpu(storage, WSBM_SYNCCPU_WRITE);
    }
  out:
    return ret;
}

int
wsbmBOSetReferenced(struct _WsbmBufferObject *buf, unsigned long handle)
{
    int ret = 0;

    wsbmBufStorageUnref(&buf->storage);
    if (buf->pool->createByReference == NULL) {
	ret = -EINVAL;
	goto out;
    }
    buf->storage = buf->pool->createByReference(buf->pool, handle);
    if (!buf->storage) {
	ret = -EINVAL;
	goto out;
    }
    buf->bufferType = WSBM_BUFFER_REF;
  out:
    return ret;
}

void
wsbmBOFreeSimple(void *ptr)
{
    free(ptr);
}

struct _WsbmBufferObject *
wsbmBOCreateSimple(struct _WsbmBufferPool *pool,
		   unsigned long size,
		   const struct _WsbmAttr *attr,
		   size_t extra_size, size_t * offset)
{
    struct _WsbmBufferObject *buf;
    struct _WsbmBufStorage *storage;

    *offset = (sizeof(*buf) + 15) & ~15;

    if (extra_size) {
	extra_size += *offset - sizeof(*buf);
    }

    buf = (struct _WsbmBufferObject *)calloc(1, sizeof(*buf) + extra_size);
    if (!buf)
	return NULL;

    storage = pool->create(pool, size, 
			   attr->setPlacement, 
			   attr->alignment,
			   attr->share,
			   attr->pin);
    if (!storage)
	goto out_err0;

    storage->destroyContainer = &wsbmBOFreeSimple;
    storage->destroyArg = buf;

    buf->storage = storage;
    buf->pool = pool;
    buf->bufferType = WSBM_BUFFER_SIMPLE;
    buf->attr = *attr;
    buf->hasAttr = 1;

    return buf;

  out_err0:
    free(buf);
    return NULL;
}

int
wsbmGenBuffers(struct _WsbmBufferPool *pool,
	       unsigned n,
	       struct _WsbmBufferObject *buffers[],
	       const struct _WsbmAttr *attr)
{
    struct _WsbmBufferObject *buf;
    int i;

    for (i = 0; i < n; ++i) {
	buf = (struct _WsbmBufferObject *)calloc(1, sizeof(*buf));
	if (!buf)
	    return -ENOMEM;

	wsbmAtomicSet(&buf->refCount, 1);
	if (attr) {
	    buf->hasAttr = 1;
	    memcpy(&buf->attr, attr, sizeof(*attr));
	}
	buf->pool = pool;
	buf->bufferType = WSBM_BUFFER_COMPLEX;
	buffers[i] = buf;
    }
    return 0;
}

void
wsbmDeleteBuffers(unsigned n, struct _WsbmBufferObject *buffers[])
{
    int i;

    for (i = 0; i < n; ++i) {
	wsbmBOUnreference(&buffers[i]);
    }
}

void
wsbmBOFence(struct _WsbmBufferObject *buf, struct _WsbmFenceObject *fence)
{
    struct _WsbmBufStorage *storage;

    storage = buf->storage;
    if (storage->pool->fence)
	storage->pool->fence(storage, fence);

}

int
wsbmBOOnList(const struct _WsbmBufferObject *buf)
{
    if (buf->storage == NULL)
	return 0;
    return wsbmAtomicRead(&buf->storage->onList);
}

void
wsbmPoolTakeDown(struct _WsbmBufferPool *pool)
{
    pool->takeDown(pool);

}

unsigned long
wsbmBOSize(struct _WsbmBufferObject *buf)
{
    unsigned long size;
    struct _WsbmBufStorage *storage;

    storage = buf->storage;
    size = storage->pool->size(storage);

    return size;

}

void
wsbmUpdateKBuf(struct _WsbmKernelBuf *kBuf,
	       uint64_t gpuOffset, uint32_t placement,
	       uint32_t fence_type_mask)
{
    kBuf->gpuOffset = gpuOffset;
    kBuf->placement = placement;
    kBuf->fence_type_mask = fence_type_mask;
}

struct _WsbmKernelBuf *
wsbmKBuf(const struct _WsbmBufferObject *buf)
{
    struct _WsbmBufStorage *storage = buf->storage;

    return storage->pool->kernel(storage);
}

struct _WsbmBufStorage *
wsbmBOStorage(struct _WsbmBufferObject *buf)
{
    return buf->storage;
}
