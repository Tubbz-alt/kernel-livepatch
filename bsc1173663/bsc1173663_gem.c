/*
 * bsc1173663_gem.c
 *
 * Fix for CVE-2019-0155, bsc#1173663 (i915_gem.c part)
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
#include "../kallsyms_relocs.h"

/* klp-ccp: from drivers/gpu/drm/i915/i915_vma.h */
static struct i915_vma *
(*klpe_i915_vma_instance)(struct drm_i915_gem_object *obj,
		  struct i915_address_space *vm,
		  const struct i915_ggtt_view *view);

static bool (*klpe_i915_vma_misplaced)(const struct i915_vma *vma,
			u64 size, u64 alignment, u64 flags);

static int __must_check (*klpe_i915_vma_unbind)(struct i915_vma *vma);


/* klp-ccp: from drivers/gpu/drm/i915/i915_gem.c */
/* New, or more specifically, renamed + patched i915_gem_object_ggtt_pin(). */
struct i915_vma *
klpp_i915_gem_object_pin(struct drm_i915_gem_object *obj,
			 struct i915_address_space *vm,
			 const struct i915_ggtt_view *view,
			 u64 size,
			 u64 alignment,
			 u64 flags)
{
	struct drm_i915_private *dev_priv = to_i915(obj->base.dev);
	struct i915_vma *vma;
	int ret;

	lockdep_assert_held(&obj->base.dev->struct_mutex);

	if (flags & PIN_MAPPABLE &&
	    (!view || view->type == I915_GGTT_VIEW_NORMAL)) {
		/* If the required space is larger than the available
		 * aperture, we will not able to find a slot for the
		 * object and unbinding the object now will be in
		 * vain. Worse, doing so may cause us to ping-pong
		 * the object in and out of the Global GTT and
		 * waste a lot of cycles under the mutex.
		 */
		if (obj->base.size > dev_priv->ggtt.mappable_end)
			return ERR_PTR(-E2BIG);

		/* If NONBLOCK is set the caller is optimistically
		 * trying to cache the full object within the mappable
		 * aperture, and *must* have a fallback in place for
		 * situations where we cannot bind the object. We
		 * can be a little more lax here and use the fallback
		 * more often to avoid costly migrations of ourselves
		 * and other objects within the aperture.
		 *
		 * Half-the-aperture is used as a simple heuristic.
		 * More interesting would to do search for a free
		 * block prior to making the commitment to unbind.
		 * That caters for the self-harm case, and with a
		 * little more heuristics (e.g. NOFAULT, NOEVICT)
		 * we could try to minimise harm to others.
		 */
		if (flags & PIN_NONBLOCK &&
		    obj->base.size > dev_priv->ggtt.mappable_end / 2)
			return ERR_PTR(-ENOSPC);
	}

	vma = (*klpe_i915_vma_instance)(obj, vm, view);
	if (unlikely(IS_ERR(vma)))
		return vma;

	if ((*klpe_i915_vma_misplaced)(vma, size, alignment, flags)) {
		if (flags & PIN_NONBLOCK) {
			if (i915_vma_is_pinned(vma) || i915_vma_is_active(vma))
				return ERR_PTR(-ENOSPC);

			if (flags & PIN_MAPPABLE &&
			    vma->fence_size > dev_priv->ggtt.mappable_end / 2)
				return ERR_PTR(-ENOSPC);
		}

		WARN(i915_vma_is_pinned(vma),
		     "bo is already pinned in ggtt with incorrect alignment:"
		     " offset=%08x, req.alignment=%llx,"
		     " req.map_and_fenceable=%d, vma->map_and_fenceable=%d\n",
		     i915_ggtt_offset(vma), alignment,
		     !!(flags & PIN_MAPPABLE),
		     i915_vma_is_map_and_fenceable(vma));
		ret = (*klpe_i915_vma_unbind)(vma);
		if (ret)
			return ERR_PTR(ret);
	}

	/*
	 * Fix CVE-2019-0155
	 *  -1 line, +1 line
	 */
	ret = klpr_i915_vma_pin(vma, size, alignment, flags);
	if (ret)
		return ERR_PTR(ret);

	return vma;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "i915_vma_instance", (void *)&klpe_i915_vma_instance, "i915" },
	{ "i915_vma_misplaced", (void *)&klpe_i915_vma_misplaced, "i915" },
	{ "i915_vma_unbind", (void *)&klpe_i915_vma_unbind, "i915" },
};

int klp_bsc1173663_gem_resolve_kallsyms(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif
