#ifndef _LIVEPATCH_BSC1176382_H
#define _LIVEPATCH_BSC1176382_H

int livepatch_bsc1176382_init(void);
void livepatch_bsc1176382_cleanup(void);


typedef struct klpp_nfs_readdir_descriptor nfs_readdir_descriptor_t;
struct nfs_entry;
struct page;

int klpp_nfs_readdir_page_filler(nfs_readdir_descriptor_t *desc, struct nfs_entry *entry,
				struct page **xdr_pages, struct page *page, unsigned int buflen);

#endif /* _LIVEPATCH_BSC1176382_H */
