#ifndef _LIVEPATCH_BSC1178700_H
#define _LIVEPATCH_BSC1178700_H

#if IS_ENABLED(CONFIG_POWERCAP)

int livepatch_bsc1178700_init(void);
static inline void livepatch_bsc1178700_cleanup(void) {}


struct inode;
struct file;

int klpp_kernfs_fop_open(struct inode *inode, struct file *file);

#else /* !IS_ENABLED(CONFIG_POWERCAP) */

static inline int livepatch_bsc1178700_init(void) { return 0; }

static inline void livepatch_bsc1178700_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_POWERCAP) */
#endif /* _LIVEPATCH_BSC1178700_H */
