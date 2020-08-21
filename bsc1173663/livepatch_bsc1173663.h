#ifndef _LIVEPATCH_BSC1173663_H
#define _LIVEPATCH_BSC1173663_H

#if IS_ENABLED(CONFIG_DRM_I915)

int livepatch_bsc1173663_init(void);
void livepatch_bsc1173663_cleanup(void);


struct i915_execbuffer;
struct i915_vma;
struct drm_i915_gem_relocation_entry;
struct drm_device;
struct drm_file;
struct drm_i915_gem_execbuffer2;
struct drm_i915_gem_exec_object2;
struct drm_syncobj;

u64
klpp_eb_relocate_entry(struct i915_execbuffer *eb,
		  struct i915_vma *vma,
		  const struct drm_i915_gem_relocation_entry *reloc);

int
klpp_i915_gem_do_execbuffer(struct drm_device *dev,
		       struct drm_file *file,
		       struct drm_i915_gem_execbuffer2 *args,
		       struct drm_i915_gem_exec_object2 *exec,
		       struct drm_syncobj **fences);

#else /* !IS_ENABLED(CONFIG_DRM_I915) */

static inline int livepatch_bsc1173663_init(void) { return 0; }

static inline void livepatch_bsc1173663_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DRM_I915) */
#endif /* _LIVEPATCH_BSC1173663_H */
