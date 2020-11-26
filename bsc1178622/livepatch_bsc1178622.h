#ifndef _LIVEPATCH_BSC1178622_H
#define _LIVEPATCH_BSC1178622_H

#if IS_ENABLED(CONFIG_VT)

int livepatch_bsc1178622_init(void);
static inline void livepatch_bsc1178622_cleanup(void) {}


struct tty_struct;

int klpp_vt_ioctl(struct tty_struct *tty,
		    unsigned int cmd, unsigned long arg);

long klpp_vt_compat_ioctl(struct tty_struct *tty,
		     unsigned int cmd, unsigned long arg);

#else /* !IS_ENABLED(CONFIG_VT) */

static inline int livepatch_bsc1178622_init(void) { return 0; }

static inline void livepatch_bsc1178622_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_VT) */
#endif /* _LIVEPATCH_BSC1178622_H */
