/*
 * livepatch_bsc1175992
 *
 * Fix for CVE-2020-24394, bsc#1175992
 *
 *  Upstream commit:
 *  22cf8419f131 ("nfsd: apply umask on fs without ACL support")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  44db378bb619837550bc0c3a0221d8feefa1a30d
 *
 *  SLE15-SP2 commit:
 *  8884ba88571c7ab89647ea5bccd45b5271817d06
 *
 *
 *  Copyright (c) 2020 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if !IS_MODULE(CONFIG_NFSD)
#error "Live patch supports only CONFIG_NFSD=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1175992.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nfsd"

/* klp-ccp: from fs/nfsd/vfs.c */
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/namei.h>
#include <linux/fsnotify.h>
#include <linux/ima.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/exportfs.h>
#include <linux/writeback.h>
#include <linux/security.h>

#ifdef CONFIG_NFSD_V3

/* klp-ccp: from fs/nfsd/nfsd.h */
#include <linux/types.h>
#include <linux/mount.h>
#include <linux/nfs.h>
#include <linux/nfs3.h>
#include <linux/nfs4.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/msg_prot.h>
#include <uapi/linux/nfsd/debug.h>
/* klp-ccp: from fs/nfsd/netns.h */
#include <net/net_namespace.h>
/* klp-ccp: from fs/nfsd/stats.h */
#include <uapi/linux/nfsd/stats.h>
/* klp-ccp: from fs/nfsd/export.h */
#include <linux/sunrpc/cache.h>
#include <uapi/linux/nfsd/export.h>
#include <linux/nfs4.h>

struct nfsd4_fs_locations {
	uint32_t locations_count;
	struct nfsd4_fs_location *locations;
/* If we're not actually serving this data ourselves (only providing a
 * list of replicas that do serve it) then we set "migrated": */
	int migrated;
};

#define MAX_SECINFO_LIST	8

struct exp_flavor_info {
	u32	pseudoflavor;
	u32	flags;
};

struct svc_export {
	struct cache_head	h;
	struct auth_domain *	ex_client;
	int			ex_flags;
	struct path		ex_path;
	kuid_t			ex_anon_uid;
	kgid_t			ex_anon_gid;
	int			ex_fsid;
	unsigned char *		ex_uuid; /* 16 byte fsid */
	struct nfsd4_fs_locations ex_fslocs;
	uint32_t		ex_nflavors;
	struct exp_flavor_info	ex_flavors[MAX_SECINFO_LIST];
	u32			ex_layout_types;
	struct nfsd4_deviceid_map *ex_devid_map;
	struct cache_detail	*cd;
	struct rcu_head		ex_rcu;
};

#define EX_ISSYNC(exp)		(!((exp)->ex_flags & NFSEXP_ASYNC))

static __be32			(*klpe_nfserrno)(int errno);

/* klp-ccp: from fs/nfsd/nfsd.h */
#define	nfserr_perm		cpu_to_be32(NFSERR_PERM)

#define	nfserr_io		cpu_to_be32(NFSERR_IO)

#define	nfserr_exist		cpu_to_be32(NFSERR_EXIST)

#define	nfserr_serverfault	cpu_to_be32(NFSERR_SERVERFAULT)

#define isdotent(n, l)	(l < 3 && n[0] == '.' && (l == 1 || n[1] == '.'))

/* klp-ccp: from fs/nfsd/nfsfh.h */
#include <linux/sunrpc/svc.h>
#include <uapi/linux/nfsd/nfsfh.h>

struct svc_fh {
	struct knfsd_fh		fh_handle;	/* FH data */
	int			fh_maxsize;	/* max size for fh_handle */
	struct dentry *		fh_dentry;	/* validated dentry */
	struct svc_export *	fh_export;	/* export pointer */

	bool			fh_locked;	/* inode locked by us */
	bool			fh_want_write;	/* remount protection taken */

#ifdef CONFIG_NFSD_V3
	bool			fh_post_saved;	/* post-op attrs saved */
	bool			fh_pre_saved;	/* pre-op attrs saved */

	/* Pre-op attributes saved during fh_lock */
	__u64			fh_pre_size;	/* size before operation */
	struct timespec		fh_pre_mtime;	/* mtime before oper */
	struct timespec		fh_pre_ctime;	/* ctime before oper */
	/*
	 * pre-op nfsv4 change attr: note must check IS_I_VERSION(inode)
	 *  to find out if it is valid.
	 */
	u64			fh_pre_change;

	/* Post-op attributes saved in fh_unlock */
	struct kstat		fh_post_attr;	/* full attrs after operation */
	u64			fh_post_change; /* nfsv4 change; see above */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_NFSD_V3 */
};

static __be32	(*klpe_fh_verify)(struct svc_rqst *, struct svc_fh *, umode_t, int);
static __be32	(*klpe_fh_compose)(struct svc_fh *, struct svc_export *, struct dentry *, struct svc_fh *);
static __be32	(*klpe_fh_update)(struct svc_fh *);

#ifdef CONFIG_NFSD_V3

static void (*klpe_fill_pre_wcc)(struct svc_fh *fhp);
static void (*klpe_fill_post_wcc)(struct svc_fh *fhp);
#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_NFSD_V3 */

static inline void
klpr_fh_lock_nested(struct svc_fh *fhp, unsigned int subclass)
{
	struct dentry	*dentry = fhp->fh_dentry;
	struct inode	*inode;

	BUG_ON(!dentry);

	if (fhp->fh_locked) {
		printk(KERN_WARNING "fh_lock: %pd2 already locked!\n",
			dentry);
		return;
	}

	inode = d_inode(dentry);
	inode_lock_nested(inode, subclass);
	(*klpe_fill_pre_wcc)(fhp);
	fhp->fh_locked = true;
}

static inline void
klpr_fh_unlock(struct svc_fh *fhp)
{
	if (fhp->fh_locked) {
		(*klpe_fill_post_wcc)(fhp);
		inode_unlock(d_inode(fhp->fh_dentry));
		fhp->fh_locked = false;
	}
}

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from fs/nfsd/vfs.c */
#endif /* CONFIG_NFSD_V3 */

#ifdef CONFIG_NFSD_V4

/* klp-ccp: from fs/nfsd/idmap.h */
#include <linux/in.h>
#include <linux/sunrpc/svc.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from fs/nfsd/vfs.c */
#endif /* CONFIG_NFSD_V4 */

/* klp-ccp: from fs/nfsd/vfs.h */
#define NFSD_MAY_EXEC			0x001 /* == MAY_EXEC */
#define NFSD_MAY_WRITE			0x002 /* == MAY_WRITE */

#define NFSD_MAY_CREATE		(NFSD_MAY_EXEC|NFSD_MAY_WRITE)

static __be32		(*klpe_nfsd_permission)(struct svc_rqst *, struct svc_export *,
				struct dentry *, int);

static inline int fh_want_write(struct svc_fh *fh)
{
	int ret;

	if (fh->fh_want_write)
		return 0;
	ret = mnt_want_write(fh->fh_export->ex_path.mnt);
	if (!ret)
		fh->fh_want_write = true;
	return ret;
}

static inline void fh_drop_write(struct svc_fh *fh)
{
	if (fh->fh_want_write) {
		fh->fh_want_write = false;
		mnt_drop_write(fh->fh_export->ex_path.mnt);
	}
}

static inline int nfsd_create_is_exclusive(int createmode)
{
	return createmode == NFS3_CREATE_EXCLUSIVE
	       || createmode == NFS4_CREATE_EXCLUSIVE4_1;
}

/* klp-ccp: from fs/nfsd/vfs.c */
static int
commit_metadata(struct svc_fh *fhp)
{
	struct inode *inode = d_inode(fhp->fh_dentry);
	const struct export_operations *export_ops = inode->i_sb->s_export_op;

	if (!EX_ISSYNC(fhp->fh_export))
		return 0;

	if (export_ops->commit_metadata)
		return export_ops->commit_metadata(inode);
	return sync_inode_metadata(inode, 1);
}

static __be32
(*klpe_nfsd_create_setattr)(struct svc_rqst *rqstp, struct svc_fh *resfhp,
			struct iattr *iap);

static void
nfsd_check_ignore_resizing(struct iattr *iap)
{
	if ((iap->ia_valid & ATTR_SIZE) && (iap->ia_size == 0))
		iap->ia_valid &= ~ATTR_SIZE;
}

__be32
klpp_nfsd_create_locked(struct svc_rqst *rqstp, struct svc_fh *fhp,
		char *fname, int flen, struct iattr *iap,
		int type, dev_t rdev, struct svc_fh *resfhp)
{
	struct dentry	*dentry, *dchild;
	struct inode	*dirp;
	__be32		err;
	__be32		err2;
	int		host_err;

	dentry = fhp->fh_dentry;
	dirp = d_inode(dentry);

	dchild = dget(resfhp->fh_dentry);
	if (!fhp->fh_locked) {
		WARN_ONCE(1, "nfsd_create: parent %pd2 not locked!\n",
				dentry);
		err = nfserr_io;
		goto out;
	}

	err = (*klpe_nfsd_permission)(rqstp, fhp->fh_export, dentry, NFSD_MAY_CREATE);
	if (err)
		goto out;

	if (!(iap->ia_valid & ATTR_MODE))
		iap->ia_mode = 0;
	iap->ia_mode = (iap->ia_mode & S_IALLUGO) | type;

	/*
	 * Fix CVE-2020-24394
	 *  +3 lines
	 */
	if (!IS_POSIXACL(dirp))
		iap->ia_mode &= ~current_umask();

	err = 0;
	host_err = 0;
	switch (type) {
	case S_IFREG:
		host_err = vfs_create(dirp, dchild, iap->ia_mode, true);
		if (!host_err)
			nfsd_check_ignore_resizing(iap);
		break;
	case S_IFDIR:
		host_err = vfs_mkdir(dirp, dchild, iap->ia_mode);
		if (!host_err && unlikely(d_unhashed(dchild))) {
			struct dentry *d;
			d = lookup_one_len(dchild->d_name.name,
					   dchild->d_parent,
					   dchild->d_name.len);
			if (IS_ERR(d)) {
				host_err = PTR_ERR(d);
				break;
			}
			if (unlikely(d_is_negative(d))) {
				dput(d);
				err = nfserr_serverfault;
				goto out;
			}
			dput(resfhp->fh_dentry);
			resfhp->fh_dentry = dget(d);
			err = (*klpe_fh_update)(resfhp);
			dput(dchild);
			dchild = d;
			if (err)
				goto out;
		}
		break;
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		host_err = vfs_mknod(dirp, dchild, iap->ia_mode, rdev);
		break;
	default:
		printk(KERN_WARNING "nfsd: bad file type %o in nfsd_create\n",
		       type);
		host_err = -EINVAL;
	}
	if (host_err < 0)
		goto out_nfserr;

	err = (*klpe_nfsd_create_setattr)(rqstp, resfhp, iap);

	/*
	 * nfsd_create_setattr already committed the child.  Transactional
	 * filesystems had a chance to commit changes for both parent and
	 * child simultaneously making the following commit_metadata a
	 * noop.
	 */
	err2 = (*klpe_nfserrno)(commit_metadata(fhp));
	if (err2)
		err = err2;
	/*
	 * Update the file handle to get the new inode info.
	 */
	if (!err)
		err = (*klpe_fh_update)(resfhp);
out:
	dput(dchild);
	return err;

out_nfserr:
	err = (*klpe_nfserrno)(host_err);
	goto out;
}

#ifdef CONFIG_NFSD_V3

__be32
klpp_do_nfsd_create(struct svc_rqst *rqstp, struct svc_fh *fhp,
		char *fname, int flen, struct iattr *iap,
		struct svc_fh *resfhp, int createmode, u32 *verifier,
	        bool *truncp, bool *created)
{
	struct dentry	*dentry, *dchild = NULL;
	struct inode	*dirp;
	__be32		err;
	int		host_err;
	__u32		v_mtime=0, v_atime=0;

	err = nfserr_perm;
	if (!flen)
		goto out;
	err = nfserr_exist;
	if (isdotent(fname, flen))
		goto out;
	if (!(iap->ia_valid & ATTR_MODE))
		iap->ia_mode = 0;
	err = (*klpe_fh_verify)(rqstp, fhp, S_IFDIR, NFSD_MAY_EXEC);
	if (err)
		goto out;

	dentry = fhp->fh_dentry;
	dirp = d_inode(dentry);

	host_err = fh_want_write(fhp);
	if (host_err)
		goto out_nfserr;

	klpr_fh_lock_nested(fhp, I_MUTEX_PARENT);

	/*
	 * Compose the response file handle.
	 */
	dchild = lookup_one_len(fname, dentry, flen);
	host_err = PTR_ERR(dchild);
	if (IS_ERR(dchild))
		goto out_nfserr;

	/* If file doesn't exist, check for permissions to create one */
	if (d_really_is_negative(dchild)) {
		err = (*klpe_fh_verify)(rqstp, fhp, S_IFDIR, NFSD_MAY_CREATE);
		if (err)
			goto out;
	}

	err = (*klpe_fh_compose)(resfhp, fhp->fh_export, dchild, fhp);
	if (err)
		goto out;

	if (nfsd_create_is_exclusive(createmode)) {
		/* solaris7 gets confused (bugid 4218508) if these have
		 * the high bit set, so just clear the high bits. If this is
		 * ever changed to use different attrs for storing the
		 * verifier, then do_open_lookup() will also need to be fixed
		 * accordingly.
		 */
		v_mtime = verifier[0]&0x7fffffff;
		v_atime = verifier[1]&0x7fffffff;
	}
	
	if (d_really_is_positive(dchild)) {
		err = 0;

		switch (createmode) {
		case NFS3_CREATE_UNCHECKED:
			if (! d_is_reg(dchild))
				goto out;
			else if (truncp) {
				/* in nfsv4, we need to treat this case a little
				 * differently.  we don't want to truncate the
				 * file now; this would be wrong if the OPEN
				 * fails for some other reason.  furthermore,
				 * if the size is nonzero, we should ignore it
				 * according to spec!
				 */
				*truncp = (iap->ia_valid & ATTR_SIZE) && !iap->ia_size;
			}
			else {
				iap->ia_valid &= ATTR_SIZE;
				goto set_attr;
			}
			break;
		case NFS3_CREATE_EXCLUSIVE:
			if (   d_inode(dchild)->i_mtime.tv_sec == v_mtime
			    && d_inode(dchild)->i_atime.tv_sec == v_atime
			    && d_inode(dchild)->i_size  == 0 ) {
				if (created)
					*created = 1;
				break;
			}
			/* fall through */
		case NFS4_CREATE_EXCLUSIVE4_1:
			if (   d_inode(dchild)->i_mtime.tv_sec == v_mtime
			    && d_inode(dchild)->i_atime.tv_sec == v_atime
			    && d_inode(dchild)->i_size  == 0 ) {
				if (created)
					*created = 1;
				goto set_attr;
			}
			/* fall through */
		case NFS3_CREATE_GUARDED:
			err = nfserr_exist;
		}
		fh_drop_write(fhp);
		goto out;
	}

	/*
	 * Fix CVE-2020-24394
	 *  +3 lines
	 */
	if (!IS_POSIXACL(dirp))
		iap->ia_mode &= ~current_umask();

	host_err = vfs_create(dirp, dchild, iap->ia_mode, true);
	if (host_err < 0) {
		fh_drop_write(fhp);
		goto out_nfserr;
	}
	if (created)
		*created = 1;

	nfsd_check_ignore_resizing(iap);

	if (nfsd_create_is_exclusive(createmode)) {
		/* Cram the verifier into atime/mtime */
		iap->ia_valid = ATTR_MTIME|ATTR_ATIME
			| ATTR_MTIME_SET|ATTR_ATIME_SET;
		/* XXX someone who knows this better please fix it for nsec */ 
		iap->ia_mtime.tv_sec = v_mtime;
		iap->ia_atime.tv_sec = v_atime;
		iap->ia_mtime.tv_nsec = 0;
		iap->ia_atime.tv_nsec = 0;
	}

 set_attr:
	err = (*klpe_nfsd_create_setattr)(rqstp, resfhp, iap);

	/*
	 * nfsd_create_setattr already committed the child
	 * (and possibly also the parent).
	 */
	if (!err)
		err = (*klpe_nfserrno)(commit_metadata(fhp));

	/*
	 * Update the filehandle to get the new inode info.
	 */
	if (!err)
		err = (*klpe_fh_update)(resfhp);

 out:
	klpr_fh_unlock(fhp);
	if (dchild && !IS_ERR(dchild))
		dput(dchild);
	fh_drop_write(fhp);
 	return err;
 
 out_nfserr:
	err = (*klpe_nfserrno)(host_err);
	goto out;
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_NFSD_V3 */



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfserrno", (void *)&klpe_nfserrno, "nfsd" },
	{ "fh_update", (void *)&klpe_fh_update, "nfsd" },
	{ "fh_verify", (void *)&klpe_fh_verify, "nfsd" },
	{ "fh_compose", (void *)&klpe_fh_compose, "nfsd" },
	{ "fill_pre_wcc", (void *)&klpe_fill_pre_wcc, "nfsd" },
	{ "fill_post_wcc", (void *)&klpe_fill_post_wcc, "nfsd" },
	{ "nfsd_permission", (void *)&klpe_nfsd_permission, "nfsd" },
	{ "nfsd_create_setattr", (void *)&klpe_nfsd_create_setattr, "nfsd" },
};

static int livepatch_bsc1175992_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1175992_module_nb = {
	.notifier_call = livepatch_bsc1175992_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1175992_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1175992_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1175992_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1175992_module_nb);
}
