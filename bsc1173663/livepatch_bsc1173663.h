#ifndef _LIVEPATCH_BSC1173663_H
#define _LIVEPATCH_BSC1173663_H

#if IS_ENABLED(CONFIG_DRM_I915)

int livepatch_bsc1173663_init(void);
void livepatch_bsc1173663_cleanup(void);


struct i915_gem_context;

void klpp_init_whitelist(struct i915_gem_context *ctx, u32 batch_len);

#else /* !IS_ENABLED(CONFIG_DRM_I915) */

static inline int livepatch_bsc1173663_init(void) { return 0; }

static inline void livepatch_bsc1173663_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DRM_I915) */
#endif /* _LIVEPATCH_BSC1173663_H */
