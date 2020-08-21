#ifndef _LIVEPATCH_BSC1173869_H
#define _LIVEPATCH_BSC1173869_H

int livepatch_bsc1173869_init(void);
void livepatch_bsc1173869_cleanup(void);


struct inode;
struct dentry;

int klpp_ext4_unlink(struct inode *dir, struct dentry *dentry);

#endif /* _LIVEPATCH_BSC1173869_H */
