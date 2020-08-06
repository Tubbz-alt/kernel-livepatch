#ifndef _LIVEPATCH_BSC1173663_H
#define _LIVEPATCH_BSC1173663_H

#if IS_ENABLED(CONFIG_DRM_I915)

int livepatch_bsc1173663_init(void);
void livepatch_bsc1173663_cleanup(void);


struct i915_gem_context;
struct intel_engine_cs;
struct drm_i915_gem_object;

int klpp_intel_engine_cmd_parser(struct i915_gem_context *ctx,
			    struct intel_engine_cs *engine,
			    struct drm_i915_gem_object *batch_obj,
			    u64 batch_start,
			    u32 batch_start_offset,
			    u32 batch_len,
			    struct drm_i915_gem_object *shadow_batch_obj,
			    u64 shadow_batch_start);

#else /* !IS_ENABLED(CONFIG_DRM_I915) */

static inline int livepatch_bsc1173663_init(void) { return 0; }

static inline void livepatch_bsc1173663_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DRM_I915) */
#endif /* _LIVEPATCH_BSC1173663_H */
