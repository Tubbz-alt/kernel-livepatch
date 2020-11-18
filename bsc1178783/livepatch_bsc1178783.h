#ifndef _LIVEPATCH_BSC1178783_H
#define _LIVEPATCH_BSC1178783_H

int livepatch_bsc1178783_init(void);
static inline void livepatch_bsc1178783_cleanup(void) {}


bool klpp_icmp_global_allow(void);

#endif /* _LIVEPATCH_BSC1178783_H */
