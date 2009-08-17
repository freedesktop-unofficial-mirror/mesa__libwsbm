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

#ifndef _WSBM_MANAGER_H_
#define _WSBM_MANAGER_H_
#include "wsbm_fencemgr.h"
#include "wsbm_util.h"
#include "wsbm_driver.h"

#define WSBM_VERSION_MAJOR 1
#define WSBM_VERSION_MINOR 1
#define WSBM_VERSION_PL 0

struct _WsbmFenceObject;
struct _WsbmBufferObject;
struct _WsbmBufferPool;


#define WSBM_ACCESS_READ         (1 << 0)
#define WSBM_ACCESS_WRITE        (1 << 1)

#define WSBM_SYNCCPU_READ        WSBM_ACCESS_READ
#define WSBM_SYNCCPU_WRITE       WSBM_ACCESS_WRITE

struct _WsbmAttr {
    uint32_t setPlacement;
    uint32_t clrPlacement;
    unsigned int alignment;
    int share;
    int pin;
};

struct _WsbmCommon {
    uint32_t refCount;
    void (*destroy) (struct _WsbmCommon *);
};

static inline const struct _WsbmAttr *
wsbmInitAttr(struct _WsbmAttr *attr,
	     uint32_t setPlacement,
	     uint32_t clrPlacement,
	     unsigned int alignment,
	     int share,
	     int pin)
{
    attr->setPlacement = setPlacement;
    attr->clrPlacement = clrPlacement;
    attr->alignment = alignment;
    attr->share = share;
    attr->pin = pin;
    return attr;
}

extern void *wsbmBOMap(struct _WsbmBufferObject *buf, unsigned mode);
extern void wsbmBOUnmap(struct _WsbmBufferObject *buf);
extern int wsbmBOSyncForCpu(struct _WsbmBufferObject *buf, unsigned mode,
			    int noBlock);
extern void wsbmBOReleaseFromCpu(struct _WsbmBufferObject *buf,
				 unsigned mode);

extern unsigned long wsbmBOOffsetHint(struct _WsbmBufferObject *buf);
extern unsigned long wsbmBOPoolOffset(struct _WsbmBufferObject *buf);

extern uint32_t wsbmBOPlacementHint(struct _WsbmBufferObject *buf);
extern struct _WsbmBufferObject *wsbmBOReference(struct _WsbmBufferObject
						 *buf);
extern void wsbmBOUnreference(struct _WsbmBufferObject **p_buf);

extern int wsbmBOData(struct _WsbmBufferObject *r_buf,
		      unsigned size, const void *data,
		      struct _WsbmBufferPool *pool,
		      const struct _WsbmAttr *attr);
extern int wsbmBOSetAttr(struct _WsbmBufferObject *buf,
			 const struct _WsbmAttr *attr);
extern int wsbmBOSubData(struct _WsbmBufferObject *buf,
			 unsigned long offset, unsigned long size,
			 const void *data,
			 int (*accelCopy) (struct _WsbmBufferObject *,
					   struct _WsbmBufferObject *));
extern struct _WsbmBufferObject *wsbmBOClone(struct _WsbmBufferObject *buf,
					     int (*accelCopy) (struct
							       _WsbmBufferObject
							       *,
							       struct
							       _WsbmBufferObject
							       *));

extern int wsbmBOGetSubData(struct _WsbmBufferObject *buf,
			    unsigned long offset, unsigned long size,
			    void *data);
extern int wsbmGenBuffers(struct _WsbmBufferPool *pool,
			  unsigned n,
			  struct _WsbmBufferObject *buffers[],
			  const struct _WsbmAttr *attr);

struct _WsbmBufferObject *wsbmBOCreateSimple(struct _WsbmBufferPool *pool,
					     unsigned long size,
					     const struct _WsbmAttr *attr,
					     size_t extra_size,
					     size_t * offset);

extern void wsbmDeleteBuffers(unsigned n,
			      struct _WsbmBufferObject *buffers[]);

extern void wsbmBOFence(struct _WsbmBufferObject *buf,
			struct _WsbmFenceObject *fence);

extern void wsbmPoolTakeDown(struct _WsbmBufferPool *pool);
extern int wsbmBOSetReferenced(struct _WsbmBufferObject *buf,
			       unsigned long handle);
unsigned long wsbmBOSize(struct _WsbmBufferObject *buf);
extern void wsbmBOWaitIdle(struct _WsbmBufferObject *buf, int lazy);
extern int wsbmBOOnList(const struct _WsbmBufferObject *buf);

extern void wsbmPoolTakeDown(struct _WsbmBufferPool *pool);

extern int wsbmInit(struct _WsbmThreadFuncs *tf);
extern void wsbmTakedown(void);
extern int wsbmIsInitialized(void);
extern void wsbmCommonDataSet(struct _WsbmCommon *common);
extern struct _WsbmCommon *wsbmCommonDataGet(void);
extern void wsbmCommonDataPut(void);
extern uint32_t wsbmKBufHandle(const struct _WsbmKernelBuf *);
extern void wsbmUpdateKBuf(struct _WsbmKernelBuf *,
			   uint64_t gpuOffset,
			   uint32_t placement, uint32_t fence_flags);

extern struct _WsbmKernelBuf *wsbmKBuf(const struct _WsbmBufferObject *buf);

#endif
