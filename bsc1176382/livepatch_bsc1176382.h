#ifndef _LIVEPATCH_BSC1176382_H
#define _LIVEPATCH_BSC1176382_H

int livepatch_bsc1176382_nfs4xdr_init(void);
void livepatch_bsc1176382_nfs4xdr_cleanup(void);
int livepatch_bsc1176382_dir_init(void);
void livepatch_bsc1176382_dir_cleanup(void);

int livepatch_bsc1176382_init(void);
void livepatch_bsc1176382_cleanup(void);


struct xdr_stream;
struct nfs_fattr;
struct nfs_fh;
struct nfs4_fs_locations;
struct nfs4_label;
struct nfs_server;
typedef struct klpp_nfs_readdir_descriptor nfs_readdir_descriptor_t;
struct nfs_entry;
struct page;

int klpp_decode_getfattr_attrs(struct xdr_stream *xdr, uint32_t *bitmap,
		struct nfs_fattr *fattr, struct nfs_fh *fh,
		struct nfs4_fs_locations *fs_loc, struct nfs4_label *label,
		const struct nfs_server *server);

int klpp_nfs_readdir_page_filler(nfs_readdir_descriptor_t *desc, struct nfs_entry *entry,
				struct page **xdr_pages, struct page *page, unsigned int buflen);

#endif /* _LIVEPATCH_BSC1176382_H */
