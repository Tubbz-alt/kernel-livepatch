/*
 * bsc1173663_gem_execbuffer.c
 *
 * Fix for CVE-2019-0155, bsc#1173663 (i915_gem_execbuffer.c part)
 *
 *  Copyright (c) 2020 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if IS_ENABLED(CONFIG_DRM_I915)
#include "bsc1173663_common.h"
#include "livepatch_bsc1173663.h"
#include "../kallsyms_relocs.h"

/* klp-ccp: from include/drm/drm_mm.h */
static int (*klpe_drm_mm_insert_node_in_range)(struct drm_mm *mm,
				struct drm_mm_node *node,
				u64 size,
				u64 alignment,
				unsigned long color,
				u64 start,
				u64 end,
				enum drm_mm_insert_mode mode);

/* klp-ccp: from include/drm/drm_syncobj.h */
static void (*klpe_drm_syncobj_replace_fence)(struct drm_syncobj *syncobj,
			       struct dma_fence *fence);

/* klp-ccp: from include/drm/drm_auth.h */
static bool (*klpe_drm_is_current_master)(struct drm_file *fpriv);

/* klp-ccp: from include/drm/drm_gem.h */
static void (*klpe_drm_gem_object_free)(struct kref *kref);

static inline void
klpr___drm_gem_object_put(struct drm_gem_object *obj)
{
	kref_put(&obj->refcount, (*klpe_drm_gem_object_free));
}

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_batch_pool.h */
static struct drm_i915_gem_object*
(*klpe_i915_gem_batch_pool_get)(struct i915_gem_batch_pool *pool, size_t size);

/* klp-ccp: from drivers/gpu/drm/i915/i915_request.h */
static struct i915_request * __must_check
(*klpe_i915_request_alloc)(struct intel_engine_cs *engine,
		   struct i915_gem_context *ctx);

static int (*klpe_i915_request_await_object)(struct i915_request *to,
			      struct drm_i915_gem_object *obj,
			      bool write);
static int (*klpe_i915_request_await_dma_fence)(struct i915_request *rq,
				 struct dma_fence *fence);

static void (*klpe_i915_request_add)(struct i915_request *rq);

static void (*klpe_i915_request_skip)(struct i915_request *request, int error);

/* klp-ccp: from drivers/gpu/drm/i915/intel_ringbuffer.h */
static u32 __must_check *(*klpe_intel_ring_begin)(struct i915_request *rq, unsigned int n);

static bool (*klpe_intel_engine_can_store_dword)(struct intel_engine_cs *engine);

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_context.h */
static void (*klpe_i915_gem_context_release)(struct kref *ctx_ref);

static inline void klpr_i915_gem_context_put(struct i915_gem_context *ctx)
{
	kref_put(&ctx->ref, (*klpe_i915_gem_context_release));
}

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_object.h */
__attribute__((nonnull))
static inline void
klpr_i915_gem_object_put(struct drm_i915_gem_object *obj)
{
	klpr___drm_gem_object_put(&obj->base);
}

/* klp-ccp: from drivers/gpu/drm/i915/i915_vma.h */
static struct i915_vma *
(*klpe_i915_vma_instance)(struct drm_i915_gem_object *obj,
		  struct i915_address_space *vm,
		  const struct i915_ggtt_view *view);

static int __must_check (*klpe_i915_vma_move_to_active)(struct i915_vma *vma,
					 struct i915_request *rq,
					 unsigned int flags);

static inline void klpr_i915_vma_put(struct i915_vma *vma)
{
	klpr_i915_gem_object_put(vma->obj);
}

static int (*klpe_i915_vma_bind)(struct i915_vma *vma, enum i915_cache_level cache_level,
		  u32 flags);

static int __must_check (*klpe_i915_vma_put_fence)(struct i915_vma *vma);

/* klp-ccp: from drivers/gpu/drm/i915/intel_drv.h */
static void (*klpe_intel_runtime_pm_get)(struct drm_i915_private *dev_priv);

static void (*klpe_intel_runtime_pm_put)(struct drm_i915_private *dev_priv);

/* klp-ccp: from drivers/gpu/drm/i915/i915_trace.h */
KLPR_TRACE_EVENT(i915_request_queue,
	    TP_PROTO(struct i915_request *rq, u32 flags),
	    TP_ARGS(rq, flags)
);


/* klp-ccp: from drivers/gpu/drm/i915/i915_drv.h */
static struct i915_vma * __must_check
(*klpe_i915_gem_object_ggtt_pin)(struct drm_i915_gem_object *obj,
			 const struct i915_ggtt_view *view,
			 u64 size,
			 u64 alignment,
			 u64 flags);

static struct page *
(*klpe_i915_gem_object_get_dirty_page)(struct drm_i915_gem_object *obj,
			       unsigned int n);

static dma_addr_t
(*klpe_i915_gem_object_get_dma_address)(struct drm_i915_gem_object *obj,
				unsigned long n);

/* klp-ccp: from drivers/gpu/drm/i915/i915_drv.h */
static void *__must_check (*klpe_i915_gem_object_pin_map)(struct drm_i915_gem_object *obj,
					   enum i915_map_type type);

static int (*klpe_i915_gem_obj_prepare_shmem_write)(struct drm_i915_gem_object *obj,
				     unsigned int *needs_clflush);

static int __must_check (*klpe_i915_mutex_lock_interruptible)(struct drm_device *dev);

static int __must_check
(*klpe_i915_gem_object_set_to_wc_domain)(struct drm_i915_gem_object *obj, bool write);
static int __must_check
(*klpe_i915_gem_object_set_to_gtt_domain)(struct drm_i915_gem_object *obj, bool write);

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_clflush.h */
static bool (*klpe_i915_gem_clflush_object)(struct drm_i915_gem_object *obj,
			     unsigned int flags);

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_execbuffer.c */
enum {
	FORCE_CPU_RELOC = 1,
	FORCE_GTT_RELOC,
	FORCE_GPU_RELOC,
#define DBG_FORCE_RELOC 0 /* choose one of the above! */
};

#define __EXEC_OBJECT_HAS_REF		BIT(31)
#define __EXEC_OBJECT_HAS_PIN		BIT(30)
#define __EXEC_OBJECT_HAS_FENCE		BIT(29)

#define __EXEC_OBJECT_NEEDS_BIAS	BIT(27)
#define __EXEC_OBJECT_INTERNAL_FLAGS	(~0u << 27) /* all of the above */

#define __EXEC_HAS_RELOC	BIT(31)

#define __EXEC_INTERNAL_FLAGS	(~0u << 30)
#define UPDATE			PIN_OFFSET_FIXED

#define __I915_EXEC_ILLEGAL_FLAGS \
	(__I915_EXEC_UNKNOWN_FLAGS | I915_EXEC_CONSTANTS_MASK)

struct i915_execbuffer {
	struct drm_i915_private *i915; /** i915 backpointer */
	struct drm_file *file; /** per-file lookup tables and limits */
	struct drm_i915_gem_execbuffer2 *args; /** ioctl parameters */
	struct drm_i915_gem_exec_object2 *exec; /** ioctl execobj[] */
	struct i915_vma **vma;
	unsigned int *flags;

	struct intel_engine_cs *engine; /** engine to queue the request to */
	struct i915_gem_context *ctx; /** context for building the request */
	struct i915_address_space *vm; /** GTT and vma for the request */

	struct i915_request *request; /** our request to build */
	struct i915_vma *batch; /** identity of the batch obj/vma */

	/** actual size of execobj[] as we may extend it for the cmdparser */
	unsigned int buffer_count;

	/** list of vma not yet bound during reservation phase */
	struct list_head unbound;

	/** list of vma that have execobj.relocation_count */
	struct list_head relocs;

	/**
	 * Track the most recently used object for relocations, as we
	 * frequently have to perform multiple relocations within the same
	 * obj/page
	 */
	struct reloc_cache {
		struct drm_mm_node node; /** temporary GTT binding */
		unsigned long vaddr; /** Current kmap address */
		unsigned long page; /** Currently mapped page index */
		unsigned int gen; /** Cached value of INTEL_GEN */
		bool use_64bit_reloc : 1;
		bool has_llc : 1;
		bool has_fence : 1;
		bool needs_unfenced : 1;

		struct i915_request *rq;
		u32 *rq_cmd;
		unsigned int rq_size;
	} reloc_cache;

	u64 invalid_flags; /** Set of execobj.flags that are invalid */
	u32 context_flags; /** Set of execobj.flags to insert from the ctx */

	u32 batch_start_offset; /** Location within object of batch */
	u32 batch_len; /** Length of batch within object */
	u32 batch_flags; /** Flags composed for emit_bb_start() */

	/**
	 * Indicate either the size of the hastable used to resolve
	 * relocation handles, or if negative that we are using a direct
	 * index into the execobj[].
	 */
	int lut_size;
	struct hlist_head *buckets; /** ht for relocation handles */
};

#define GEN8_HIGH_ADDRESS_BIT 47
static inline u64 gen8_canonical_addr(u64 address)
{
	return sign_extend64(address, GEN8_HIGH_ADDRESS_BIT);
}

static inline bool klpp_eb_use_cmdparser(const struct i915_execbuffer *eb)
{
	/*
	 * Fix CVE-2019-0155
	 *  -1 line, +2 lines
	 */
	return (intel_engine_needs_cmd_parser(eb->engine) &&
		eb->args->batch_len);
}

static int eb_create(struct i915_execbuffer *eb)
{
	if (!(eb->args->flags & I915_EXEC_HANDLE_LUT)) {
		unsigned int size = 1 + ilog2(eb->buffer_count);

		/*
		 * Without a 1:1 association between relocation handles and
		 * the execobject[] index, we instead create a hashtable.
		 * We size it dynamically based on available memory, starting
		 * first with 1:1 assocative hash and scaling back until
		 * the allocation succeeds.
		 *
		 * Later on we use a positive lut_size to indicate we are
		 * using this hashtable, and a negative value to indicate a
		 * direct lookup.
		 */
		do {
			gfp_t flags;

			/* While we can still reduce the allocation size, don't
			 * raise a warning and allow the allocation to fail.
			 * On the last pass though, we want to try as hard
			 * as possible to perform the allocation and warn
			 * if it fails.
			 */
			flags = GFP_KERNEL;
			if (size > 1)
				flags |= __GFP_NORETRY | __GFP_NOWARN;

			eb->buckets = kzalloc(sizeof(struct hlist_head) << size,
					      flags);
			if (eb->buckets)
				break;
		} while (--size);

		if (unlikely(!size))
			return -ENOMEM;

		eb->lut_size = size;
	} else {
		eb->lut_size = -eb->buffer_count;
	}

	return 0;
}

static inline void __eb_unreserve_vma(struct i915_vma *vma, unsigned int flags)
{
	GEM_BUG_ON(!(flags & __EXEC_OBJECT_HAS_PIN));

	if (unlikely(flags & __EXEC_OBJECT_HAS_FENCE))
		__i915_vma_unpin_fence(vma);

	__i915_vma_unpin(vma);
}

static inline int use_cpu_reloc(const struct reloc_cache *cache,
				const struct drm_i915_gem_object *obj)
{
	if (!i915_gem_object_has_struct_page(obj))
		return false;

	if (DBG_FORCE_RELOC == FORCE_CPU_RELOC)
		return true;

	if (DBG_FORCE_RELOC == FORCE_GTT_RELOC)
		return false;

	return (cache->has_llc ||
		obj->cache_dirty ||
		obj->cache_level != I915_CACHE_NONE);
}

static int eb_select_context(struct i915_execbuffer *eb)
{
	struct i915_gem_context *ctx;

	ctx = i915_gem_context_lookup(eb->file->driver_priv, eb->args->rsvd1);
	if (unlikely(!ctx))
		return -ENOENT;

	eb->ctx = ctx;
	eb->vm = ctx->ppgtt ? &ctx->ppgtt->vm : &eb->i915->ggtt.vm;

	eb->context_flags = 0;
	if (ctx->flags & CONTEXT_NO_ZEROMAP)
		eb->context_flags |= __EXEC_OBJECT_NEEDS_BIAS;

	return 0;
}

static int (*klpe_eb_lookup_vmas)(struct i915_execbuffer *eb);

static struct i915_vma *
eb_get_vma(const struct i915_execbuffer *eb, unsigned long handle)
{
	if (eb->lut_size < 0) {
		if (handle >= -eb->lut_size)
			return NULL;
		return eb->vma[handle];
	} else {
		struct hlist_head *head;
		struct i915_vma *vma;

		head = &eb->buckets[hash_32(handle, eb->lut_size)];
		hlist_for_each_entry(vma, head, exec_node) {
			if (vma->exec_handle == handle)
				return vma;
		}
		return NULL;
	}
}

static void (*klpe_eb_release_vmas)(const struct i915_execbuffer *eb);

static void eb_destroy(const struct i915_execbuffer *eb)
{
	GEM_BUG_ON(eb->reloc_cache.rq);

	if (eb->lut_size > 0)
		kfree(eb->buckets);
}

static inline u64
relocation_target(const struct drm_i915_gem_relocation_entry *reloc,
		  const struct i915_vma *target)
{
	return gen8_canonical_addr((int)reloc->delta + target->node.start);
}

static void reloc_cache_init(struct reloc_cache *cache,
			     struct drm_i915_private *i915)
{
	cache->page = -1;
	cache->vaddr = 0;
	/* Must be a variable in the struct to allow GCC to unroll. */
	cache->gen = INTEL_GEN(i915);
	cache->has_llc = HAS_LLC(i915);
	cache->use_64bit_reloc = HAS_64BIT_RELOC(i915);
	cache->has_fence = cache->gen < 4;
	cache->needs_unfenced = INTEL_INFO(i915)->unfenced_needs_alignment;
	cache->node.allocated = false;
	cache->rq = NULL;
	cache->rq_size = 0;
}

static inline void *unmask_page(unsigned long p)
{
	return (void *)(uintptr_t)(p & PAGE_MASK);
}

static inline unsigned int unmask_flags(unsigned long p)
{
	return p & ~PAGE_MASK;
}

#define KMAP 0x4 /* after CLFLUSH_FLAGS */

static inline struct i915_ggtt *cache_to_ggtt(struct reloc_cache *cache)
{
	struct drm_i915_private *i915 =
		container_of(cache, struct i915_execbuffer, reloc_cache)->i915;
	return &i915->ggtt;
}

static void (*klpe_reloc_gpu_flush)(struct reloc_cache *cache);

static void *klpr_reloc_kmap(struct drm_i915_gem_object *obj,
			struct reloc_cache *cache,
			unsigned long page)
{
	void *vaddr;

	if (cache->vaddr) {
		kunmap_atomic(unmask_page(cache->vaddr));
	} else {
		unsigned int flushes;
		int err;

		err = (*klpe_i915_gem_obj_prepare_shmem_write)(obj, &flushes);
		if (err)
			return ERR_PTR(err);

		BUILD_BUG_ON(KMAP & CLFLUSH_FLAGS);
		BUILD_BUG_ON((KMAP | CLFLUSH_FLAGS) & PAGE_MASK);

		cache->vaddr = flushes | KMAP;
		cache->node.mm = (void *)obj;
		if (flushes)
			mb();
	}

	vaddr = kmap_atomic((*klpe_i915_gem_object_get_dirty_page)(obj, page));
	cache->vaddr = unmask_flags(cache->vaddr) | (unsigned long)vaddr;
	cache->page = page;

	return vaddr;
}

static void *klpr_reloc_iomap(struct drm_i915_gem_object *obj,
			 struct reloc_cache *cache,
			 unsigned long page)
{
	struct i915_ggtt *ggtt = cache_to_ggtt(cache);
	unsigned long offset;
	void *vaddr;

	if (cache->vaddr) {
		io_mapping_unmap_atomic((void __force __iomem *) unmask_page(cache->vaddr));
	} else {
		struct i915_vma *vma;
		int err;

		if (use_cpu_reloc(cache, obj))
			return NULL;

		err = (*klpe_i915_gem_object_set_to_gtt_domain)(obj, true);
		if (err)
			return ERR_PTR(err);

		vma = (*klpe_i915_gem_object_ggtt_pin)(obj, NULL, 0, 0,
					       PIN_MAPPABLE |
					       PIN_NONBLOCK |
					       PIN_NONFAULT);
		if (IS_ERR(vma)) {
			memset(&cache->node, 0, sizeof(cache->node));
			err = (*klpe_drm_mm_insert_node_in_range)
				(&ggtt->vm.mm, &cache->node,
				 PAGE_SIZE, 0, I915_COLOR_UNEVICTABLE,
				 0, ggtt->mappable_end,
				 DRM_MM_INSERT_LOW);
			if (err) /* no inactive aperture space, use cpu reloc */
				return NULL;
		} else {
			err = (*klpe_i915_vma_put_fence)(vma);
			if (err) {
				i915_vma_unpin(vma);
				return ERR_PTR(err);
			}

			cache->node.start = vma->node.start;
			cache->node.mm = (void *)vma;
		}
	}

	offset = cache->node.start;
	if (cache->node.allocated) {
		wmb();
		ggtt->vm.insert_page(&ggtt->vm,
				     (*klpe_i915_gem_object_get_dma_address)(obj, page),
				     offset, I915_CACHE_NONE, 0);
	} else {
		offset += page << PAGE_SHIFT;
	}

	vaddr = (void __force *)io_mapping_map_atomic_wc(&ggtt->iomap,
							 offset);
	cache->page = page;
	cache->vaddr = (unsigned long)vaddr;

	return vaddr;
}

static void *klpr_reloc_vaddr(struct drm_i915_gem_object *obj,
			 struct reloc_cache *cache,
			 unsigned long page)
{
	void *vaddr;

	if (cache->page == page) {
		vaddr = unmask_page(cache->vaddr);
	} else {
		vaddr = NULL;
		if ((cache->vaddr & KMAP) == 0)
			vaddr = klpr_reloc_iomap(obj, cache, page);
		if (!vaddr)
			vaddr = klpr_reloc_kmap(obj, cache, page);
	}

	return vaddr;
}

static void clflush_write32(u32 *addr, u32 value, unsigned int flushes)
{
	if (unlikely(flushes & (CLFLUSH_BEFORE | CLFLUSH_AFTER))) {
		if (flushes & CLFLUSH_BEFORE) {
			clflushopt(addr);
			mb();
		}

		*addr = value;

		/*
		 * Writes to the same cacheline are serialised by the CPU
		 * (including clflush). On the write path, we only require
		 * that it hits memory in an orderly fashion and place
		 * mb barriers at the start and end of the relocation phase
		 * to ensure ordering of clflush wrt to the system.
		 */
		if (flushes & CLFLUSH_AFTER)
			clflushopt(addr);
	} else
		*addr = value;
}

static int klpr___reloc_gpu_alloc(struct i915_execbuffer *eb,
			     struct i915_vma *vma,
			     unsigned int len)
{
	struct reloc_cache *cache = &eb->reloc_cache;
	struct drm_i915_gem_object *obj;
	struct i915_request *rq;
	struct i915_vma *batch;
	u32 *cmd;
	int err;

	GEM_BUG_ON(vma->obj->write_domain & I915_GEM_DOMAIN_CPU);

	obj = (*klpe_i915_gem_batch_pool_get)(&eb->engine->batch_pool, PAGE_SIZE);
	if (IS_ERR(obj))
		return PTR_ERR(obj);

	cmd = (*klpe_i915_gem_object_pin_map)(obj,
				      cache->has_llc ?
				      I915_MAP_FORCE_WB :
				      I915_MAP_FORCE_WC);
	i915_gem_object_unpin_pages(obj);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	err = (*klpe_i915_gem_object_set_to_wc_domain)(obj, false);
	if (err)
		goto err_unmap;

	batch = (*klpe_i915_vma_instance)(obj, vma->vm, NULL);
	if (IS_ERR(batch)) {
		err = PTR_ERR(batch);
		goto err_unmap;
	}

	err = klpr_i915_vma_pin(batch, 0, 0, PIN_USER | PIN_NONBLOCK);
	if (err)
		goto err_unmap;

	rq = (*klpe_i915_request_alloc)(eb->engine, eb->ctx);
	if (IS_ERR(rq)) {
		err = PTR_ERR(rq);
		goto err_unpin;
	}

	err = (*klpe_i915_request_await_object)(rq, vma->obj, true);
	if (err)
		goto err_request;

	err = eb->engine->emit_bb_start(rq,
					batch->node.start, PAGE_SIZE,
					cache->gen > 5 ? 0 : I915_DISPATCH_SECURE);
	if (err)
		goto err_request;

	GEM_BUG_ON(!reservation_object_test_signaled_rcu(batch->resv, true));
	err = (*klpe_i915_vma_move_to_active)(batch, rq, 0);
	if (err)
		goto skip_request;

	err = (*klpe_i915_vma_move_to_active)(vma, rq, EXEC_OBJECT_WRITE);
	if (err)
		goto skip_request;

	rq->batch = batch;
	i915_vma_unpin(batch);

	cache->rq = rq;
	cache->rq_cmd = cmd;
	cache->rq_size = 0;

	/* Return with batch mapping (cmd) still pinned */
	return 0;

skip_request:
	(*klpe_i915_request_skip)(rq, err);
err_request:
	(*klpe_i915_request_add)(rq);
err_unpin:
	i915_vma_unpin(batch);
err_unmap:
	i915_gem_object_unpin_map(obj);
	return err;
}

static u32 *klpp_reloc_gpu(struct i915_execbuffer *eb,
		      struct i915_vma *vma,
		      unsigned int len)
{
	struct reloc_cache *cache = &eb->reloc_cache;
	u32 *cmd;

	if (cache->rq_size > PAGE_SIZE/sizeof(u32) - (len + 1))
		(*klpe_reloc_gpu_flush)(cache);

	if (unlikely(!cache->rq)) {
		int err;

		/* If we need to copy for the cmdparser, we will stall anyway */
		/*
		 * Fix CVE-2019-0155
		 *  -1 line, +2 lines
		 * Upstream patches eb_use_cmdparser() to also return
		 * true for the gen9 blitter engine. For the
		 * additional I915_DISPATCH_SECURE test below,
		 * c.f. the comment on I915_EXEC_SECURE handling in
		 * the patched klpp_i915_gem_do_execbuffer().
		 */
		if (klpp_eb_use_cmdparser(eb) ||
		    (!(eb->batch_flags & I915_DISPATCH_SECURE) && klpp_is_gen9_blt(eb->engine)))
			return ERR_PTR(-EWOULDBLOCK);

		if (!(*klpe_intel_engine_can_store_dword)(eb->engine))
			return ERR_PTR(-ENODEV);

		err = klpr___reloc_gpu_alloc(eb, vma, len);
		if (unlikely(err))
			return ERR_PTR(err);
	}

	cmd = cache->rq_cmd + cache->rq_size;
	cache->rq_size += len;

	return cmd;
}

static u64
klpp_relocate_entry(struct i915_vma *vma,
	       const struct drm_i915_gem_relocation_entry *reloc,
	       struct i915_execbuffer *eb,
	       const struct i915_vma *target)
{
	u64 offset = reloc->offset;
	u64 target_offset = relocation_target(reloc, target);
	bool wide = eb->reloc_cache.use_64bit_reloc;
	void *vaddr;

	if (!eb->reloc_cache.vaddr &&
	    (DBG_FORCE_RELOC == FORCE_GPU_RELOC ||
	     !reservation_object_test_signaled_rcu(vma->resv, true))) {
		const unsigned int gen = eb->reloc_cache.gen;
		unsigned int len;
		u32 *batch;
		u64 addr;

		if (wide)
			len = offset & 7 ? 8 : 5;
		else if (gen >= 4)
			len = 4;
		else
			len = 3;

		batch = klpp_reloc_gpu(eb, vma, len);
		if (IS_ERR(batch))
			goto repeat;

		addr = gen8_canonical_addr(vma->node.start + offset);
		if (wide) {
			if (offset & 7) {
				*batch++ = MI_STORE_DWORD_IMM_GEN4;
				*batch++ = lower_32_bits(addr);
				*batch++ = upper_32_bits(addr);
				*batch++ = lower_32_bits(target_offset);

				addr = gen8_canonical_addr(addr + 4);

				*batch++ = MI_STORE_DWORD_IMM_GEN4;
				*batch++ = lower_32_bits(addr);
				*batch++ = upper_32_bits(addr);
				*batch++ = upper_32_bits(target_offset);
			} else {
				*batch++ = (MI_STORE_DWORD_IMM_GEN4 | (1 << 21)) + 1;
				*batch++ = lower_32_bits(addr);
				*batch++ = upper_32_bits(addr);
				*batch++ = lower_32_bits(target_offset);
				*batch++ = upper_32_bits(target_offset);
			}
		} else if (gen >= 6) {
			*batch++ = MI_STORE_DWORD_IMM_GEN4;
			*batch++ = 0;
			*batch++ = addr;
			*batch++ = target_offset;
		} else if (gen >= 4) {
			*batch++ = MI_STORE_DWORD_IMM_GEN4 | MI_USE_GGTT;
			*batch++ = 0;
			*batch++ = addr;
			*batch++ = target_offset;
		} else {
			*batch++ = MI_STORE_DWORD_IMM | MI_MEM_VIRTUAL;
			*batch++ = addr;
			*batch++ = target_offset;
		}

		goto out;
	}

repeat:
	vaddr = klpr_reloc_vaddr(vma->obj, &eb->reloc_cache, offset >> PAGE_SHIFT);
	if (IS_ERR(vaddr))
		return PTR_ERR(vaddr);

	clflush_write32(vaddr + offset_in_page(offset),
			lower_32_bits(target_offset),
			eb->reloc_cache.vaddr);

	if (wide) {
		offset += sizeof(u32);
		target_offset >>= 32;
		wide = false;
		goto repeat;
	}

out:
	return target->node.start | UPDATE;
}

u64
klpp_eb_relocate_entry(struct i915_execbuffer *eb,
		  struct i915_vma *vma,
		  const struct drm_i915_gem_relocation_entry *reloc)
{
	struct i915_vma *target;
	int err;

	/* we've already hold a reference to all valid objects */
	target = eb_get_vma(eb, reloc->target_handle);
	if (unlikely(!target))
		return -ENOENT;

	/* Validate that the target is in a valid r/w GPU domain */
	if (unlikely(reloc->write_domain & (reloc->write_domain - 1))) {
		KLPR_DRM_DEBUG("reloc with multiple write domains: "
			  "target %d offset %d "
			  "read %08x write %08x",
			  reloc->target_handle,
			  (int) reloc->offset,
			  reloc->read_domains,
			  reloc->write_domain);
		return -EINVAL;
	}
	if (unlikely((reloc->write_domain | reloc->read_domains)
		     & ~I915_GEM_GPU_DOMAINS)) {
		KLPR_DRM_DEBUG("reloc with read/write non-GPU domains: "
			  "target %d offset %d "
			  "read %08x write %08x",
			  reloc->target_handle,
			  (int) reloc->offset,
			  reloc->read_domains,
			  reloc->write_domain);
		return -EINVAL;
	}

	if (reloc->write_domain) {
		*target->exec_flags |= EXEC_OBJECT_WRITE;

		/*
		 * Sandybridge PPGTT errata: We need a global gtt mapping
		 * for MI and pipe_control writes because the gpu doesn't
		 * properly redirect them through the ppgtt for non_secure
		 * batchbuffers.
		 */
		if (reloc->write_domain == I915_GEM_DOMAIN_INSTRUCTION &&
		    IS_GEN6(eb->i915)) {
			err = (*klpe_i915_vma_bind)(target, target->obj->cache_level,
					    PIN_GLOBAL);
			if (WARN_ONCE(err,
				      "Unexpected failure to bind target VMA!"))
				return err;
		}
	}

	/*
	 * If the relocation already has the right value in it, no
	 * more work needs to be done.
	 */
	if (!DBG_FORCE_RELOC &&
	    gen8_canonical_addr(target->node.start) == reloc->presumed_offset)
		return 0;

	/* Check that the relocation address is valid... */
	if (unlikely(reloc->offset >
		     vma->size - (eb->reloc_cache.use_64bit_reloc ? 8 : 4))) {
		KLPR_DRM_DEBUG("Relocation beyond object bounds: "
			  "target %d offset %d size %d.\n",
			  reloc->target_handle,
			  (int)reloc->offset,
			  (int)vma->size);
		return -EINVAL;
	}
	if (unlikely(reloc->offset & 3)) {
		KLPR_DRM_DEBUG("Relocation not 4-byte aligned: "
			  "target %d offset %d.\n",
			  reloc->target_handle,
			  (int)reloc->offset);
		return -EINVAL;
	}

	/*
	 * If we write into the object, we need to force the synchronisation
	 * barrier, either with an asynchronous clflush or if we executed the
	 * patching using the GPU (though that should be serialised by the
	 * timeline). To be completely sure, and since we are required to
	 * do relocations we are already stalling, disable the user's opt
	 * out of our synchronisation.
	 */
	*vma->exec_flags &= ~EXEC_OBJECT_ASYNC;

	/* and update the user's relocation entry */
	return klpp_relocate_entry(vma, reloc, eb, target);
}

static int (*klpe_eb_relocate_vma)(struct i915_execbuffer *eb, struct i915_vma *vma);

static int (*klpe_eb_relocate_slow)(struct i915_execbuffer *eb);

static int klpr_eb_relocate(struct i915_execbuffer *eb)
{
	if ((*klpe_eb_lookup_vmas)(eb))
		goto slow;

	/* The objects are in their final locations, apply the relocations. */
	if (eb->args->flags & __EXEC_HAS_RELOC) {
		struct i915_vma *vma;

		list_for_each_entry(vma, &eb->relocs, reloc_link) {
			if ((*klpe_eb_relocate_vma)(eb, vma))
				goto slow;
		}
	}

	return 0;

slow:
	return (*klpe_eb_relocate_slow)(eb);
}

static int klpr_eb_move_to_gpu(struct i915_execbuffer *eb)
{
	const unsigned int count = eb->buffer_count;
	unsigned int i;
	int err;

	for (i = 0; i < count; i++) {
		unsigned int flags = eb->flags[i];
		struct i915_vma *vma = eb->vma[i];
		struct drm_i915_gem_object *obj = vma->obj;

		if (flags & EXEC_OBJECT_CAPTURE) {
			struct i915_capture_list *capture;

			capture = kmalloc(sizeof(*capture), GFP_KERNEL);
			if (unlikely(!capture))
				return -ENOMEM;

			capture->next = eb->request->capture_list;
			capture->vma = eb->vma[i];
			eb->request->capture_list = capture;
		}

		/*
		 * If the GPU is not _reading_ through the CPU cache, we need
		 * to make sure that any writes (both previous GPU writes from
		 * before a change in snooping levels and normal CPU writes)
		 * caught in that cache are flushed to main memory.
		 *
		 * We want to say
		 *   obj->cache_dirty &&
		 *   !(obj->cache_coherent & I915_BO_CACHE_COHERENT_FOR_READ)
		 * but gcc's optimiser doesn't handle that as well and emits
		 * two jumps instead of one. Maybe one day...
		 */
		if (unlikely(obj->cache_dirty & ~obj->cache_coherent)) {
			if ((*klpe_i915_gem_clflush_object)(obj, 0))
				flags &= ~EXEC_OBJECT_ASYNC;
		}

		if (flags & EXEC_OBJECT_ASYNC)
			continue;

		err = (*klpe_i915_request_await_object)
			(eb->request, obj, flags & EXEC_OBJECT_WRITE);
		if (err)
			return err;
	}

	for (i = 0; i < count; i++) {
		unsigned int flags = eb->flags[i];
		struct i915_vma *vma = eb->vma[i];

		err = (*klpe_i915_vma_move_to_active)(vma, eb->request, flags);
		if (unlikely(err)) {
			(*klpe_i915_request_skip)(eb->request, err);
			return err;
		}

		__eb_unreserve_vma(vma, flags);
		vma->exec_flags = NULL;

		if (unlikely(flags & __EXEC_OBJECT_HAS_REF))
			klpr_i915_vma_put(vma);
	}
	eb->exec = NULL;

	/* Unconditionally flush any chipset caches (for streaming writes). */
	i915_gem_chipset_flush(eb->i915);

	return 0;
}

static int klpr_i915_reset_gen7_sol_offsets(struct i915_request *rq)
{
	u32 *cs;
	int i;

	if (!IS_GEN7(rq->i915) || rq->engine->id != RCS) {
		KLPR_DRM_DEBUG("sol reset is gen7/rcs only\n");
		return -EINVAL;
	}

	cs = (*klpe_intel_ring_begin)(rq, 4 * 2 + 2);
	if (IS_ERR(cs))
		return PTR_ERR(cs);

	*cs++ = MI_LOAD_REGISTER_IMM(4);
	for (i = 0; i < 4; i++) {
		*cs++ = i915_mmio_reg_offset(GEN7_SO_WRITE_OFFSET(i));
		*cs++ = 0;
	}
	*cs++ = MI_NOOP;
	intel_ring_advance(rq, cs);

	return 0;
}

/*
 * New.
 * Notes:
 * I.)
 * - We reach here only for gen7 and gen9 devices, everything else
 *   doesn't invoke the cmd parser.
 * - The only caller, i915_gem_do_execbuffer() passes either
 *   ctx->ppgtt as eb->vm if !NULL or the device's ggtt,
 *   c.f. eb_select_context().
 * - ctx->ppgtt is set iff USES_FULL_PPGTT(dev) returns true,
 *   c.f. i915_gem_create_context().
 * - USES_FULL_PPGTT(dev) is set if enable_ppgtt >= 2.
 * - enable_ppgtt is defaulted in intel_sanitize_enable_ppgtt() to 2
 *   on gen8+ and to 1 or zero before, but can be overriden by users.
 *
 * intel_sanitize_enable_ppgtt() gets patched upstream to always force
 * enable_ppgtt to >= 2 during intialization on gen9, something which
 * cannot be done retroactively on a running system from a livepatch.
 * However, the existing default satisfies this constraint. Note that
 * vm->has_read_only gets set for IS_VALLEYVIEW() GGTTs and gen8+
 * ppgts. IS_VALLEYVIEW() devices of gen7 exist, but gen7 is caught by
 * the CMDPARSER_USES_GGTT() if clause. In conclusion, if
 * vm->has_read_only evaluates to true in the else-if clause below,
 * then vm is guaranteed to a ppgtt.
 *
 * II.)
 * The shadow batch buffer obj is drawn from the engine's
 * ->batch_pool. The very same batch_pool is also used by reloc_gpu()
 * for applying relocations programmatically from another batch buffer
 * run on the GPU itself. Upstream permanently disables reloc_gpu() if
 * the parser is to be used and thus, the two don't interfere with
 * each other. However, with livepatching, we can potentially
 * encounter a batch buffer previously (and still) bound as RW by
 * reloc_gpu() and thei915_gem_object_set_readonly() below wouldn't
 * have any effect in this case. Note that i915_gem_batch_pool_fini(),
 * indirectly called from intel_engines_park() after 100ms of
 * inactivity, would drain all (inactive) batch buffers from the
 * pool. So, instead of playing tricky games with i915_vma_unbind()
 * below, wait for this event to happen. Empirically, even on a busy
 * desktop system this has been observed to happen once in a while.
 * Vice versa, even though reloc_gpu() gets livepatched here as well,
 * an unpatched implementation (during KLP transition or after
 * revert/downgrade) might encounter a batch buffer from the pool
 * already bound as RO by us below. As these don't get written to from
 * the GPU, this isn't a problem.
 */
static struct i915_vma *
klpp_shadow_batch_pin(struct i915_execbuffer *eb, struct drm_i915_gem_object *obj)
{
	struct drm_i915_private *dev_priv = eb->i915;
	struct i915_address_space *vm;
	u64 flags;

	/*
	 * PPGTT backed shadow buffers must be mapped RO, to prevent
	 * post-scan tampering
	 */
	if (KLPP_CMDPARSER_USES_GGTT(dev_priv)) {
		flags = PIN_GLOBAL;
		vm = &dev_priv->ggtt.vm;
		return (*klpe_i915_gem_object_ggtt_pin)(obj, NULL, 0, 0, 0);
	} else if (eb->vm->has_read_only) {
		struct i915_vma *ret;
		bool orig_readonly;
		flags = PIN_USER;
		vm = eb->vm;
		orig_readonly = i915_gem_object_is_readonly(obj);
		i915_gem_object_set_readonly(obj);
		ret = klpp_i915_gem_object_pin(obj, vm, NULL, 0, 0, flags);
		obj->base.vma_node.readonly = orig_readonly;
		return ret;
	} else {
		KLPR_DRM_DEBUG("Cannot prevent post-scan tampering without RO capable vm\n");
		return ERR_PTR(-EINVAL);
	}
}

/*
 * Fix CVE-2019-0155
 *  -1 line, +1 line
 */
static struct i915_vma *klpp_eb_parse(struct i915_execbuffer *eb)
{
	struct drm_i915_gem_object *shadow_batch_obj;
	struct i915_vma *vma;
	/*
	 * Fix CVE-2019-0155
	 *  +2 lines
	 */
	u64 batch_start;
	u64 shadow_batch_start;
	int err;

	shadow_batch_obj = (*klpe_i915_gem_batch_pool_get)(&eb->engine->batch_pool,
						   PAGE_ALIGN(eb->batch_len));
	if (IS_ERR(shadow_batch_obj))
		return ERR_CAST(shadow_batch_obj);

	/*
	 * Fix CVE-2019-0155
	 *  +3 lines
	 */
	vma = klpp_shadow_batch_pin(eb, shadow_batch_obj);
	if (IS_ERR(vma))
		goto out;

	/*
	 * Fix CVE-2019-0155
	 *  +4 lines
	 */
	batch_start = gen8_canonical_addr(eb->batch->node.start) +
		      eb->batch_start_offset;

	shadow_batch_start = gen8_canonical_addr(vma->node.start);

	/*
	 * Fix CVE-2019-0155
	 *  -6 lines, +8 lines
	 */
	err = klpp_intel_engine_cmd_parser(eb->ctx,
				      eb->engine,
				      eb->batch->obj,
				      batch_start,
				      eb->batch_start_offset,
				      eb->batch_len,
				      shadow_batch_obj,
				      shadow_batch_start);
	if (err) {
		/*
		 * Fix CVE-2019-0155
		 *  -1 line, +10 lines
		 */
		i915_vma_unpin(vma);

		/*
		 * Unsafe GGTT-backed buffers can still be submitted safely
		 * as non-secure.
		 * For PPGTT backing however, we have no choice but to forcibly
		 * reject unsafe buffers
		 */
		if (KLPP_CMDPARSER_USES_GGTT(eb->i915) && (err == -EACCES))
			/* Execute original buffer non-secure */
			vma = NULL;
		else
			vma = ERR_PTR(err);
		goto out;
	}

	/*
	 * Fix CVE-2019-0155
	 *  -3 lines
	 */

	eb->vma[eb->buffer_count] = i915_vma_get(vma);
	eb->flags[eb->buffer_count] =
		__EXEC_OBJECT_HAS_PIN | __EXEC_OBJECT_HAS_REF;
	vma->exec_flags = &eb->flags[eb->buffer_count];
	eb->buffer_count++;
	/*
	 * Fix CVE-2019-0155
	 *  +2 lines
	 */
	eb->batch_start_offset = 0;
	eb->batch = vma;

	/*
	 * Fix CVE-2019-0155
	 *  +3 lines
	 */
	if (KLPP_CMDPARSER_USES_GGTT(eb->i915))
		eb->batch_flags |= I915_DISPATCH_SECURE;

	/*
	 * Fix CVE-2019-0155
	 *  +2 lines
	 */
	/* We should not have changed overall length */
	GEM_BUG_ON(eb->batch_len != eb->batch->size - eb->batch_start_offset);

out:
	i915_gem_object_unpin_pages(shadow_batch_obj);
	return vma;
}

static void
add_to_client(struct i915_request *rq, struct drm_file *file)
{
	rq->file_priv = file->driver_priv;
	list_add_tail(&rq->client_link, &rq->file_priv->mm.request_list);
}

static int klpr_eb_submit(struct i915_execbuffer *eb)
{
	int err;

	err = klpr_eb_move_to_gpu(eb);
	if (err)
		return err;

	if (eb->args->flags & I915_EXEC_GEN7_SOL_RESET) {
		err = klpr_i915_reset_gen7_sol_offsets(eb->request);
		if (err)
			return err;
	}

	err = eb->engine->emit_bb_start(eb->request,
					eb->batch->node.start +
					eb->batch_start_offset,
					eb->batch_len,
					eb->batch_flags);
	if (err)
		return err;

	return 0;
}

static unsigned int
gen8_dispatch_bsd_engine(struct drm_i915_private *dev_priv,
			 struct drm_file *file)
{
	struct drm_i915_file_private *file_priv = file->driver_priv;

	/* Check whether the file_priv has already selected one ring. */
	if ((int)file_priv->bsd_engine < 0)
		file_priv->bsd_engine = atomic_fetch_xor(1,
			 &dev_priv->mm.bsd_engine_dispatch_index);

	return file_priv->bsd_engine;
}

#define I915_USER_RINGS (4)

static const enum intel_engine_id (*klpe_user_ring_map)[I915_USER_RINGS + 1];

static struct intel_engine_cs *
klpr_eb_select_engine(struct drm_i915_private *dev_priv,
		 struct drm_file *file,
		 struct drm_i915_gem_execbuffer2 *args)
{
	unsigned int user_ring_id = args->flags & I915_EXEC_RING_MASK;
	struct intel_engine_cs *engine;

	if (user_ring_id > I915_USER_RINGS) {
		KLPR_DRM_DEBUG("execbuf with unknown ring: %u\n", user_ring_id);
		return NULL;
	}

	if ((user_ring_id != I915_EXEC_BSD) &&
	    ((args->flags & I915_EXEC_BSD_MASK) != 0)) {
		KLPR_DRM_DEBUG("execbuf with non bsd ring but with invalid "
			  "bsd dispatch flags: %d\n", (int)(args->flags));
		return NULL;
	}

	if (user_ring_id == I915_EXEC_BSD && HAS_BSD2(dev_priv)) {
		unsigned int bsd_idx = args->flags & I915_EXEC_BSD_MASK;

		if (bsd_idx == I915_EXEC_BSD_DEFAULT) {
			bsd_idx = gen8_dispatch_bsd_engine(dev_priv, file);
		} else if (bsd_idx >= I915_EXEC_BSD_RING1 &&
			   bsd_idx <= I915_EXEC_BSD_RING2) {
			bsd_idx >>= I915_EXEC_BSD_SHIFT;
			bsd_idx--;
		} else {
			KLPR_DRM_DEBUG("execbuf with unknown bsd ring: %u\n",
				  bsd_idx);
			return NULL;
		}

		engine = dev_priv->engine[_VCS(bsd_idx)];
	} else {
		engine = dev_priv->engine[(*klpe_user_ring_map)[user_ring_id]];
	}

	if (!engine) {
		KLPR_DRM_DEBUG("execbuf with invalid ring: %u\n", user_ring_id);
		return NULL;
	}

	return engine;
}

static int
klpr_await_fence_array(struct i915_execbuffer *eb,
		  struct drm_syncobj **fences)
{
	const unsigned int nfences = eb->args->num_cliprects;
	unsigned int n;
	int err;

	for (n = 0; n < nfences; n++) {
		struct drm_syncobj *syncobj;
		struct dma_fence *fence;
		unsigned int flags;

		syncobj = ptr_unpack_bits(fences[n], &flags, 2);
		if (!(flags & I915_EXEC_FENCE_WAIT))
			continue;

		fence = drm_syncobj_fence_get(syncobj);
		if (!fence)
			return -EINVAL;

		err = (*klpe_i915_request_await_dma_fence)(eb->request, fence);
		dma_fence_put(fence);
		if (err < 0)
			return err;
	}

	return 0;
}

static void
klpr_signal_fence_array(struct i915_execbuffer *eb,
		   struct drm_syncobj **fences)
{
	const unsigned int nfences = eb->args->num_cliprects;
	struct dma_fence * const fence = &eb->request->fence;
	unsigned int n;

	for (n = 0; n < nfences; n++) {
		struct drm_syncobj *syncobj;
		unsigned int flags;

		syncobj = ptr_unpack_bits(fences[n], &flags, 2);
		if (!(flags & I915_EXEC_FENCE_SIGNAL))
			continue;

		(*klpe_drm_syncobj_replace_fence)(syncobj, fence);
	}
}

int
klpp_i915_gem_do_execbuffer(struct drm_device *dev,
		       struct drm_file *file,
		       struct drm_i915_gem_execbuffer2 *args,
		       struct drm_i915_gem_exec_object2 *exec,
		       struct drm_syncobj **fences)
{
	struct i915_execbuffer eb;
	struct dma_fence *in_fence = NULL;
	struct sync_file *out_fence = NULL;
	int out_fence_fd = -1;
	int err;

	BUILD_BUG_ON(__EXEC_INTERNAL_FLAGS & ~__I915_EXEC_ILLEGAL_FLAGS);
	BUILD_BUG_ON(__EXEC_OBJECT_INTERNAL_FLAGS &
		     ~__EXEC_OBJECT_UNKNOWN_FLAGS);

	eb.i915 = to_i915(dev);
	eb.file = file;
	eb.args = args;
	if (DBG_FORCE_RELOC || !(args->flags & I915_EXEC_NO_RELOC))
		args->flags |= __EXEC_HAS_RELOC;

	eb.exec = exec;
	eb.vma = (struct i915_vma **)(exec + args->buffer_count + 1);
	eb.vma[0] = NULL;
	eb.flags = (unsigned int *)(eb.vma + args->buffer_count + 1);

	eb.invalid_flags = __EXEC_OBJECT_UNKNOWN_FLAGS;
	if (((*klpe_i915_modparams).enable_ppgtt >= 2))
		eb.invalid_flags |= EXEC_OBJECT_NEEDS_GTT;
	reloc_cache_init(&eb.reloc_cache, eb.i915);

	eb.buffer_count = args->buffer_count;
	eb.batch_start_offset = args->batch_start_offset;
	eb.batch_len = args->batch_len;

	eb.batch_flags = 0;
	if (args->flags & I915_EXEC_SECURE) {
		/*
		 * Fix CVE-2019-0155
		 *  +-0 lines
		 * Upstream returns -EPERM here for gen6+.
		 * But we don't want to break existing applications
		 * from a livepatch and continue to let root shoot
		 * him/hersef into the foot, if he/she wants to.
		 * In order for this to continue to work, we must
		 * invoke the parser for gen9 below only if
		 * I915_EXEC_SECURE had not been set -- otherwise
		 * eb->batch will be made to point to a PPGTT backed
		 * shadow buffer.
		 */
		if (!(*klpe_drm_is_current_master)(file) || !capable(CAP_SYS_ADMIN))
		    return -EPERM;

		eb.batch_flags |= I915_DISPATCH_SECURE;
	}
	if (args->flags & I915_EXEC_IS_PINNED)
		eb.batch_flags |= I915_DISPATCH_PINNED;

	eb.engine = klpr_eb_select_engine(eb.i915, file, args);
	if (!eb.engine)
		return -EINVAL;

	if (args->flags & I915_EXEC_RESOURCE_STREAMER) {
		if (!HAS_RESOURCE_STREAMER(eb.i915)) {
			KLPR_DRM_DEBUG("RS is only allowed for Haswell, Gen8 and above\n");
			return -EINVAL;
		}
		if (eb.engine->id != RCS) {
			KLPR_DRM_DEBUG("RS is not available on %s\n",
				 eb.engine->name);
			return -EINVAL;
		}

		eb.batch_flags |= I915_DISPATCH_RS;
	}

	if (args->flags & I915_EXEC_FENCE_IN) {
		in_fence = sync_file_get_fence(lower_32_bits(args->rsvd2));
		if (!in_fence)
			return -EINVAL;
	}

	if (args->flags & I915_EXEC_FENCE_OUT) {
		out_fence_fd = get_unused_fd_flags(O_CLOEXEC);
		if (out_fence_fd < 0) {
			err = out_fence_fd;
			goto err_in_fence;
		}
	}

	err = eb_create(&eb);
	if (err)
		goto err_out_fence;

	GEM_BUG_ON(!eb.lut_size);

	err = eb_select_context(&eb);
	if (unlikely(err))
		goto err_destroy;

	/*
	 * Take a local wakeref for preparing to dispatch the execbuf as
	 * we expect to access the hardware fairly frequently in the
	 * process. Upon first dispatch, we acquire another prolonged
	 * wakeref that we hold until the GPU has been idle for at least
	 * 100ms.
	 */
	(*klpe_intel_runtime_pm_get)(eb.i915);

	err = (*klpe_i915_mutex_lock_interruptible)(dev);
	if (err)
		goto err_rpm;

	err = klpr_eb_relocate(&eb);
	if (err) {
		/*
		 * If the user expects the execobject.offset and
		 * reloc.presumed_offset to be an exact match,
		 * as for using NO_RELOC, then we cannot update
		 * the execobject.offset until we have completed
		 * relocation.
		 */
		args->flags &= ~__EXEC_HAS_RELOC;
		goto err_vma;
	}

	if (unlikely(*eb.batch->exec_flags & EXEC_OBJECT_WRITE)) {
		KLPR_DRM_DEBUG("Attempting to use self-modifying batch buffer\n");
		err = -EINVAL;
		goto err_vma;
	}
	if (eb.batch_start_offset > eb.batch->size ||
	    eb.batch_len > eb.batch->size - eb.batch_start_offset) {
		KLPR_DRM_DEBUG("Attempting to use out-of-bounds batch\n");
		err = -EINVAL;
		goto err_vma;
	}

	/*
	 * Fix CVE-2019-0155
	 *  +2 lines
	 */
	if (eb.batch_len == 0)
		eb.batch_len = eb.batch->size - eb.batch_start_offset;

	/*
	 * Fix CVE-2019-0155
	 *  -1 line, +2 lines
	 * See the comment at the I915_EXEC_SECURE handling code
	 * above: don't invoke the parser for gen9 if root called this
	 * with I915_EXEC_SECURE set. This is important to retain
	 * original behaviour and to not change eb->batch to a
	 * shadow buffer.
	 */
	if (klpp_eb_use_cmdparser(&eb) ||
	    (!(eb.batch_flags & I915_DISPATCH_SECURE) && klpp_is_gen9_blt(eb.engine))) {
		struct i915_vma *vma;

		/*
		 * Fix CVE-2019-0155
		 *  -1 line, +1 line
		 */
		vma = klpp_eb_parse(&eb);
		if (IS_ERR(vma)) {
			err = PTR_ERR(vma);
			goto err_vma;
		}

		/*
		 * Fix CVE-2019-0155
		 *  -14 lines
		 */
	}

	/*
	 * Fix CVE-2019-0155
	 *  -2 lines
	 */

	/*
	 * snb/ivb/vlv conflate the "batch in ppgtt" bit with the "non-secure
	 * batch" bit. Hence we need to pin secure batches into the global gtt.
	 * hsw should have this fixed, but bdw mucks it up again. */
	if (eb.batch_flags & I915_DISPATCH_SECURE) {
		struct i915_vma *vma;

		/*
		 * So on first glance it looks freaky that we pin the batch here
		 * outside of the reservation loop. But:
		 * - The batch is already pinned into the relevant ppgtt, so we
		 *   already have the backing storage fully allocated.
		 * - No other BO uses the global gtt (well contexts, but meh),
		 *   so we don't really have issues with multiple objects not
		 *   fitting due to fragmentation.
		 * So this is actually safe.
		 */
		vma = (*klpe_i915_gem_object_ggtt_pin)(eb.batch->obj, NULL, 0, 0, 0);
		if (IS_ERR(vma)) {
			err = PTR_ERR(vma);
			goto err_vma;
		}

		eb.batch = vma;
	}

	/* All GPU relocation batches must be submitted prior to the user rq */
	GEM_BUG_ON(eb.reloc_cache.rq);

	/* Allocate a request for this batch buffer nice and early. */
	eb.request = (*klpe_i915_request_alloc)(eb.engine, eb.ctx);
	if (IS_ERR(eb.request)) {
		err = PTR_ERR(eb.request);
		goto err_batch_unpin;
	}

	if (in_fence) {
		err = (*klpe_i915_request_await_dma_fence)(eb.request, in_fence);
		if (err < 0)
			goto err_request;
	}

	if (fences) {
		err = klpr_await_fence_array(&eb, fences);
		if (err)
			goto err_request;
	}

	if (out_fence_fd != -1) {
		out_fence = sync_file_create(&eb.request->fence);
		if (!out_fence) {
			err = -ENOMEM;
			goto err_request;
		}
	}

	/*
	 * Whilst this request exists, batch_obj will be on the
	 * active_list, and so will hold the active reference. Only when this
	 * request is retired will the the batch_obj be moved onto the
	 * inactive_list and lose its active reference. Hence we do not need
	 * to explicitly hold another reference here.
	 */
	eb.request->batch = eb.batch;

	klpr_trace_i915_request_queue(eb.request, eb.batch_flags);
	err = klpr_eb_submit(&eb);
err_request:
	(*klpe_i915_request_add)(eb.request);
	add_to_client(eb.request, file);

	if (fences)
		klpr_signal_fence_array(&eb, fences);

	if (out_fence) {
		if (err == 0) {
			fd_install(out_fence_fd, out_fence->file);
			args->rsvd2 &= GENMASK_ULL(31, 0); /* keep in-fence */
			args->rsvd2 |= (u64)out_fence_fd << 32;
			out_fence_fd = -1;
		} else {
			fput(out_fence->file);
		}
	}

err_batch_unpin:
	if (eb.batch_flags & I915_DISPATCH_SECURE)
		i915_vma_unpin(eb.batch);
err_vma:
	if (eb.exec)
		(*klpe_eb_release_vmas)(&eb);
	mutex_unlock(&dev->struct_mutex);
err_rpm:
	(*klpe_intel_runtime_pm_put)(eb.i915);
	klpr_i915_gem_context_put(eb.ctx);
err_destroy:
	eb_destroy(&eb);
err_out_fence:
	if (out_fence_fd != -1)
		put_unused_fd(out_fence_fd);
err_in_fence:
	dma_fence_put(in_fence);
	return err;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__tracepoint_i915_request_queue",
	  (void *)&klpe___tracepoint_i915_request_queue, "i915" },
	{ "user_ring_map", (void *)&klpe_user_ring_map, "i915" },
	{ "drm_mm_insert_node_in_range",
	  (void *)&klpe_drm_mm_insert_node_in_range, "drm" },
	{ "drm_syncobj_replace_fence", (void *)&klpe_drm_syncobj_replace_fence,
	  "drm" },
	{ "drm_is_current_master", (void *)&klpe_drm_is_current_master, "drm" },
	{ "drm_gem_object_free", (void *)&klpe_drm_gem_object_free, "drm" },
	{ "i915_gem_batch_pool_get", (void *)&klpe_i915_gem_batch_pool_get,
	  "i915" },
	{ "i915_request_skip", (void *)&klpe_i915_request_skip, "i915" },
	{ "i915_request_alloc", (void *)&klpe_i915_request_alloc, "i915" },
	{ "i915_request_await_object", (void *)&klpe_i915_request_await_object,
	  "i915" },
	{ "i915_request_await_dma_fence",
	  (void *)&klpe_i915_request_await_dma_fence, "i915" },
	{ "i915_request_add", (void *)&klpe_i915_request_add, "i915" },
	{ "intel_ring_begin", (void *)&klpe_intel_ring_begin, "i915" },
	{ "intel_engine_can_store_dword",
	  (void *)&klpe_intel_engine_can_store_dword, "i915" },
	{ "i915_gem_context_release", (void *)&klpe_i915_gem_context_release,
	  "i915" },
	{ "i915_vma_instance", (void *)&klpe_i915_vma_instance, "i915" },
	{ "i915_vma_move_to_active", (void *)&klpe_i915_vma_move_to_active,
	  "i915" },
	{ "i915_vma_bind", (void *)&klpe_i915_vma_bind, "i915" },
	{ "i915_vma_put_fence", (void *)&klpe_i915_vma_put_fence, "i915" },
	{ "intel_runtime_pm_get", (void *)&klpe_intel_runtime_pm_get, "i915" },
	{ "intel_runtime_pm_put", (void *)&klpe_intel_runtime_pm_put, "i915" },
	{ "i915_mutex_lock_interruptible",
	  (void *)&klpe_i915_mutex_lock_interruptible, "i915" },
	{ "i915_gem_object_set_to_wc_domain",
	  (void *)&klpe_i915_gem_object_set_to_wc_domain, "i915" },
	{ "i915_gem_object_set_to_gtt_domain",
	  (void *)&klpe_i915_gem_object_set_to_gtt_domain, "i915" },
	{ "i915_gem_object_ggtt_pin", (void *)&klpe_i915_gem_object_ggtt_pin,
	  "i915" },
	{ "i915_gem_object_pin_map", (void *)&klpe_i915_gem_object_pin_map,
	  "i915" },
	{ "i915_gem_object_get_dma_address",
	  (void *)&klpe_i915_gem_object_get_dma_address, "i915" },
	{ "i915_gem_obj_prepare_shmem_write",
	  (void *)&klpe_i915_gem_obj_prepare_shmem_write, "i915" },
	{ "i915_gem_object_get_dirty_page",
	  (void *)&klpe_i915_gem_object_get_dirty_page, "i915" },
	{ "i915_gem_clflush_object",
	  (void *)&klpe_i915_gem_clflush_object, "i915" },
	{ "eb_lookup_vmas", (void *)&klpe_eb_lookup_vmas, "i915" },
	{ "eb_release_vmas", (void *)&klpe_eb_release_vmas, "i915" },
	{ "reloc_gpu_flush", (void *)&klpe_reloc_gpu_flush, "i915" },
	{ "eb_relocate_vma", (void *)&klpe_eb_relocate_vma, "i915" },
	{ "eb_relocate_slow", (void *)&klpe_eb_relocate_slow, "i915" },
};

int klp_bsc1173663_gem_execbuffer_resolve_kallsyms(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif
