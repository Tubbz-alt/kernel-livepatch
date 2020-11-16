#ifndef _LIVEPATCH_BSC1178046_H
#define _LIVEPATCH_BSC1178046_H

int livepatch_bsc1178046_init(void);
void livepatch_bsc1178046_cleanup(void);


struct work_struct;

void klpp_btrfs_async_reclaim_metadata_space(struct work_struct *work);

#endif /* _LIVEPATCH_BSC1178046_H */
