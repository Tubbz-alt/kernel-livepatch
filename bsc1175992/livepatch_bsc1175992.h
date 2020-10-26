#ifndef _LIVEPATCH_BSC1175992_H
#define _LIVEPATCH_BSC1175992_H

int livepatch_bsc1175992_init(void);
void livepatch_bsc1175992_cleanup(void);


struct svc_rqst;
struct svc_fh;
struct iattr;

__be32
klpp_nfsd_create_locked(struct svc_rqst *rqstp, struct svc_fh *fhp,
		char *fname, int flen, struct iattr *iap,
		int type, dev_t rdev, struct svc_fh *resfhp);

__be32
klpp_do_nfsd_create(struct svc_rqst *rqstp, struct svc_fh *fhp,
		char *fname, int flen, struct iattr *iap,
		struct svc_fh *resfhp, int createmode, u32 *verifier,
	        bool *truncp, bool *created);

#endif /* _LIVEPATCH_BSC1175992_H */
