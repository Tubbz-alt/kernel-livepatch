/*
 * bsc1176382_nfs4xdr
 *
 * Fix for CVE-2020-25212, bsc#1176382 (fs/nfs/nfs4xdr.c part)
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

#if !IS_MODULE(CONFIG_NFS_V4)
#error "Live patch supports only CONFIG_NFS_V4=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1176382.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nfsv4"

/* klp-ccp: from fs/nfs/nfs4xdr.c */
#include <linux/param.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/pagemap.h>
#include <linux/kdev_t.h>
#include <linux/module.h>
#include <linux/utsname.h>
#include <linux/sunrpc/clnt.h>

/* klp-ccp: from include/linux/sunrpc/debug.h */
#if IS_ENABLED(CONFIG_SUNRPC_DEBUG)

static unsigned int		(*klpe_nfs_debug);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from include/linux/sunrpc/xdr.h */
static __be32 *(*klpe_xdr_inline_decode)(struct xdr_stream *xdr, size_t nbytes);

static ssize_t (*klpe_xdr_stream_decode_string_dup)(struct xdr_stream *xdr, char **str,
		size_t maxlen, gfp_t gfp_flags);

static inline ssize_t
klpr_xdr_stream_decode_u32(struct xdr_stream *xdr, __u32 *ptr)
{
	const size_t count = sizeof(*ptr);
	__be32 *p = (*klpe_xdr_inline_decode)(xdr, count);

	if (unlikely(!p))
		return -EBADMSG;
	*ptr = be32_to_cpup(p);
	return 0;
}

static inline ssize_t
klpr_xdr_stream_decode_opaque_inline(struct xdr_stream *xdr, void **ptr, size_t maxlen)
{
	__be32 *p;
	__u32 len;

	*ptr = NULL;
	if (unlikely(klpr_xdr_stream_decode_u32(xdr, &len) < 0))
		return -EBADMSG;
	if (len != 0) {
		p = (*klpe_xdr_inline_decode)(xdr, len);
		if (unlikely(!p))
			return -EBADMSG;
		if (unlikely(len > maxlen))
			return -EMSGSIZE;
		*ptr = p;
	}
	return len;
}

/* klp-ccp: from fs/nfs/nfs4xdr.c */
#include <linux/sunrpc/msg_prot.h>
#include <linux/sunrpc/gss_api.h>
#include <linux/nfs.h>
#include <linux/nfs4.h>
#include <linux/nfs_fs.h>

/* klp-ccp: from include/linux/nfs_fs.h */
# undef ifdebug
# ifdef NFS_DEBUG
#  define ifdebug(fac)		if (unlikely((*klpe_nfs_debug) & NFSDBG_##fac))
# else
#error "klp-ccp: a preceeding branch should have been taken"
# endif

/* klp-ccp: from fs/nfs/nfs4_fs.h */
#include <linux/seqlock.h>

/* klp-ccp: from fs/nfs/internal.h */
#include <linux/security.h>
#include <linux/wait_bit.h>
/* klp-ccp: from fs/nfs/nfs4idmap.h */
#include <linux/uidgid.h>

static int (*klpe_nfs_map_name_to_uid)(const struct nfs_server *, const char *, size_t, kuid_t *);
static int (*klpe_nfs_map_group_to_gid)(const struct nfs_server *, const char *, size_t, kgid_t *);

/* klp-ccp: from fs/nfs/pnfs.h */
#include <linux/nfs_fs.h>
#include <linux/nfs_page.h>
#include <linux/workqueue.h>
/* klp-ccp: from fs/nfs/netns.h */
#include <linux/nfs4.h>
#include <net/net_namespace.h>

/* klp-ccp: from fs/nfs/nfs4xdr.c */
#define NFSDBG_FACILITY		NFSDBG_XDR

static const umode_t (*klpe_nfs_type2fmt)[];

static void klpr_print_overflow_msg(const char *func, const struct xdr_stream *xdr)
{
	dprintk("nfs: %s: prematurely hit end of receive buffer. "
		"Remaining buffer length is %tu words.\n",
		func, xdr->end - xdr->p);
}

static int (*klpe_decode_opaque_inline)(struct xdr_stream *xdr, unsigned int *len, char **string);

static int (*klpe_decode_attr_bitmap)(struct xdr_stream *xdr, uint32_t *bitmap);

static int (*klpe_decode_attr_length)(struct xdr_stream *xdr, uint32_t *attrlen, unsigned int *savep);

static int klpr_decode_attr_type(struct xdr_stream *xdr, uint32_t *bitmap, uint32_t *type)
{
	__be32 *p;
	int ret = 0;

	*type = 0;
	if (unlikely(bitmap[0] & (FATTR4_WORD0_TYPE - 1U)))
		return -EIO;
	if (likely(bitmap[0] & FATTR4_WORD0_TYPE)) {
		p = (*klpe_xdr_inline_decode)(xdr, 4);
		if (unlikely(!p))
			goto out_overflow;
		*type = be32_to_cpup(p);
		if (*type < NF4REG || *type > NF4NAMEDATTR) {
			dprintk("%s: bad type %d\n", __func__, *type);
			return -EIO;
		}
		bitmap[0] &= ~FATTR4_WORD0_TYPE;
		ret = NFS_ATTR_FATTR_TYPE;
	}
	dprintk("%s: type=0%o\n", __func__, (*klpe_nfs_type2fmt)[*type]);
	return ret;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_change(struct xdr_stream *xdr, uint32_t *bitmap, uint64_t *change)
{
	__be32 *p;
	int ret = 0;

	*change = 0;
	if (unlikely(bitmap[0] & (FATTR4_WORD0_CHANGE - 1U)))
		return -EIO;
	if (likely(bitmap[0] & FATTR4_WORD0_CHANGE)) {
		p = (*klpe_xdr_inline_decode)(xdr, 8);
		if (unlikely(!p))
			goto out_overflow;
		xdr_decode_hyper(p, change);
		bitmap[0] &= ~FATTR4_WORD0_CHANGE;
		ret = NFS_ATTR_FATTR_CHANGE;
	}
	dprintk("%s: change attribute=%Lu\n", __func__,
			(unsigned long long)*change);
	return ret;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_size(struct xdr_stream *xdr, uint32_t *bitmap, uint64_t *size)
{
	__be32 *p;
	int ret = 0;

	*size = 0;
	if (unlikely(bitmap[0] & (FATTR4_WORD0_SIZE - 1U)))
		return -EIO;
	if (likely(bitmap[0] & FATTR4_WORD0_SIZE)) {
		p = (*klpe_xdr_inline_decode)(xdr, 8);
		if (unlikely(!p))
			goto out_overflow;
		xdr_decode_hyper(p, size);
		bitmap[0] &= ~FATTR4_WORD0_SIZE;
		ret = NFS_ATTR_FATTR_SIZE;
	}
	dprintk("%s: file size=%Lu\n", __func__, (unsigned long long)*size);
	return ret;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_fsid(struct xdr_stream *xdr, uint32_t *bitmap, struct nfs_fsid *fsid)
{
	__be32 *p;
	int ret = 0;

	fsid->major = 0;
	fsid->minor = 0;
	if (unlikely(bitmap[0] & (FATTR4_WORD0_FSID - 1U)))
		return -EIO;
	if (likely(bitmap[0] & FATTR4_WORD0_FSID)) {
		p = (*klpe_xdr_inline_decode)(xdr, 16);
		if (unlikely(!p))
			goto out_overflow;
		p = xdr_decode_hyper(p, &fsid->major);
		xdr_decode_hyper(p, &fsid->minor);
		bitmap[0] &= ~FATTR4_WORD0_FSID;
		ret = NFS_ATTR_FATTR_FSID;
	}
	dprintk("%s: fsid=(0x%Lx/0x%Lx)\n", __func__,
			(unsigned long long)fsid->major,
			(unsigned long long)fsid->minor);
	return ret;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_error(struct xdr_stream *xdr, uint32_t *bitmap, int32_t *res)
{
	__be32 *p;

	if (unlikely(bitmap[0] & (FATTR4_WORD0_RDATTR_ERROR - 1U)))
		return -EIO;
	if (likely(bitmap[0] & FATTR4_WORD0_RDATTR_ERROR)) {
		p = (*klpe_xdr_inline_decode)(xdr, 4);
		if (unlikely(!p))
			goto out_overflow;
		bitmap[0] &= ~FATTR4_WORD0_RDATTR_ERROR;
		*res = -be32_to_cpup(p);
	}
	return 0;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_filehandle(struct xdr_stream *xdr, uint32_t *bitmap, struct nfs_fh *fh)
{
	__be32 *p;
	int len;

	if (fh != NULL)
		memset(fh, 0, sizeof(*fh));

	if (unlikely(bitmap[0] & (FATTR4_WORD0_FILEHANDLE - 1U)))
		return -EIO;
	if (likely(bitmap[0] & FATTR4_WORD0_FILEHANDLE)) {
		p = (*klpe_xdr_inline_decode)(xdr, 4);
		if (unlikely(!p))
			goto out_overflow;
		len = be32_to_cpup(p);
		if (len > NFS4_FHSIZE)
			return -EIO;
		p = (*klpe_xdr_inline_decode)(xdr, len);
		if (unlikely(!p))
			goto out_overflow;
		if (fh != NULL) {
			memcpy(fh->data, p, len);
			fh->size = len;
		}
		bitmap[0] &= ~FATTR4_WORD0_FILEHANDLE;
	}
	return 0;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_fileid(struct xdr_stream *xdr, uint32_t *bitmap, uint64_t *fileid)
{
	__be32 *p;
	int ret = 0;

	*fileid = 0;
	if (unlikely(bitmap[0] & (FATTR4_WORD0_FILEID - 1U)))
		return -EIO;
	if (likely(bitmap[0] & FATTR4_WORD0_FILEID)) {
		p = (*klpe_xdr_inline_decode)(xdr, 8);
		if (unlikely(!p))
			goto out_overflow;
		xdr_decode_hyper(p, fileid);
		bitmap[0] &= ~FATTR4_WORD0_FILEID;
		ret = NFS_ATTR_FATTR_FILEID;
	}
	dprintk("%s: fileid=%Lu\n", __func__, (unsigned long long)*fileid);
	return ret;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_mounted_on_fileid(struct xdr_stream *xdr, uint32_t *bitmap, uint64_t *fileid)
{
	__be32 *p;
	int ret = 0;

	*fileid = 0;
	if (unlikely(bitmap[1] & (FATTR4_WORD1_MOUNTED_ON_FILEID - 1U)))
		return -EIO;
	if (likely(bitmap[1] & FATTR4_WORD1_MOUNTED_ON_FILEID)) {
		p = (*klpe_xdr_inline_decode)(xdr, 8);
		if (unlikely(!p))
			goto out_overflow;
		xdr_decode_hyper(p, fileid);
		bitmap[1] &= ~FATTR4_WORD1_MOUNTED_ON_FILEID;
		ret = NFS_ATTR_FATTR_MOUNTED_ON_FILEID;
	}
	dprintk("%s: fileid=%Lu\n", __func__, (unsigned long long)*fileid);
	return ret;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int (*klpe_decode_pathname)(struct xdr_stream *xdr, struct nfs4_pathname *path);

static int klpr_decode_attr_fs_locations(struct xdr_stream *xdr, uint32_t *bitmap, struct nfs4_fs_locations *res)
{
	int n;
	__be32 *p;
	int status = -EIO;

	if (unlikely(bitmap[0] & (FATTR4_WORD0_FS_LOCATIONS -1U)))
		goto out;
	status = 0;
	if (unlikely(!(bitmap[0] & FATTR4_WORD0_FS_LOCATIONS)))
		goto out;
	bitmap[0] &= ~FATTR4_WORD0_FS_LOCATIONS;
	status = -EIO;
	/* Ignore borken servers that return unrequested attrs */
	if (unlikely(res == NULL))
		goto out;
	dprintk("%s: fsroot:\n", __func__);
	status = (*klpe_decode_pathname)(xdr, &res->fs_path);
	if (unlikely(status != 0))
		goto out;
	p = (*klpe_xdr_inline_decode)(xdr, 4);
	if (unlikely(!p))
		goto out_overflow;
	n = be32_to_cpup(p);
	if (n <= 0)
		goto out_eio;
	for (res->nlocations = 0; res->nlocations < n; res->nlocations++) {
		u32 m;
		struct nfs4_fs_location *loc;

		if (res->nlocations == NFS4_FS_LOCATIONS_MAXENTRIES)
			break;
		loc = &res->locations[res->nlocations];
		p = (*klpe_xdr_inline_decode)(xdr, 4);
		if (unlikely(!p))
			goto out_overflow;
		m = be32_to_cpup(p);

		dprintk("%s: servers:\n", __func__);
		for (loc->nservers = 0; loc->nservers < m; loc->nservers++) {
			struct nfs4_string *server;

			if (loc->nservers == NFS4_FS_LOCATION_MAXSERVERS) {
				unsigned int i;
				dprintk("%s: using first %u of %u servers "
					"returned for location %u\n",
					__func__,
					NFS4_FS_LOCATION_MAXSERVERS,
					m, res->nlocations);
				for (i = loc->nservers; i < m; i++) {
					unsigned int len;
					char *data;
					status = (*klpe_decode_opaque_inline)(xdr, &len, &data);
					if (unlikely(status != 0))
						goto out_eio;
				}
				break;
			}
			server = &loc->servers[loc->nservers];
			status = (*klpe_decode_opaque_inline)(xdr, &server->len, &server->data);
			if (unlikely(status != 0))
				goto out_eio;
			dprintk("%s ",server->data);
		}
		status = (*klpe_decode_pathname)(xdr, &loc->rootpath);
		if (unlikely(status != 0))
			goto out_eio;
	}
	if (res->nlocations != 0)
		status = NFS_ATTR_FATTR_V4_LOCATIONS;
out:
	dprintk("%s: fs_locations done, error = %d\n", __func__, status);
	return status;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
out_eio:
	status = -EIO;
	goto out;
}

static int klpr_decode_attr_mode(struct xdr_stream *xdr, uint32_t *bitmap, umode_t *mode)
{
	uint32_t tmp;
	__be32 *p;
	int ret = 0;

	*mode = 0;
	if (unlikely(bitmap[1] & (FATTR4_WORD1_MODE - 1U)))
		return -EIO;
	if (likely(bitmap[1] & FATTR4_WORD1_MODE)) {
		p = (*klpe_xdr_inline_decode)(xdr, 4);
		if (unlikely(!p))
			goto out_overflow;
		tmp = be32_to_cpup(p);
		*mode = tmp & ~S_IFMT;
		bitmap[1] &= ~FATTR4_WORD1_MODE;
		ret = NFS_ATTR_FATTR_MODE;
	}
	dprintk("%s: file mode=0%o\n", __func__, (unsigned int)*mode);
	return ret;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_nlink(struct xdr_stream *xdr, uint32_t *bitmap, uint32_t *nlink)
{
	__be32 *p;
	int ret = 0;

	*nlink = 1;
	if (unlikely(bitmap[1] & (FATTR4_WORD1_NUMLINKS - 1U)))
		return -EIO;
	if (likely(bitmap[1] & FATTR4_WORD1_NUMLINKS)) {
		p = (*klpe_xdr_inline_decode)(xdr, 4);
		if (unlikely(!p))
			goto out_overflow;
		*nlink = be32_to_cpup(p);
		bitmap[1] &= ~FATTR4_WORD1_NUMLINKS;
		ret = NFS_ATTR_FATTR_NLINK;
	}
	dprintk("%s: nlink=%u\n", __func__, (unsigned int)*nlink);
	return ret;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static ssize_t klpr_decode_nfs4_string(struct xdr_stream *xdr,
		struct nfs4_string *name, gfp_t gfp_flags)
{
	ssize_t ret;

	ret = (*klpe_xdr_stream_decode_string_dup)(xdr, &name->data,
			XDR_MAX_NETOBJ, gfp_flags);
	name->len = 0;
	if (ret > 0)
		name->len = ret;
	return ret;
}

static int klpr_decode_attr_owner(struct xdr_stream *xdr, uint32_t *bitmap,
		const struct nfs_server *server, kuid_t *uid,
		struct nfs4_string *owner_name)
{
	ssize_t len;
	char *p;

	*uid = make_kuid(&init_user_ns, -2);
	if (unlikely(bitmap[1] & (FATTR4_WORD1_OWNER - 1U)))
		return -EIO;
	if (!(bitmap[1] & FATTR4_WORD1_OWNER))
		return 0;
	bitmap[1] &= ~FATTR4_WORD1_OWNER;

	if (owner_name != NULL) {
		len = klpr_decode_nfs4_string(xdr, owner_name, GFP_NOWAIT);
		if (len <= 0)
			goto out;
		dprintk("%s: name=%s\n", __func__, owner_name->data);
		return NFS_ATTR_FATTR_OWNER_NAME;
	} else {
		len = klpr_xdr_stream_decode_opaque_inline(xdr, (void **)&p,
				XDR_MAX_NETOBJ);
		if (len <= 0 || (*klpe_nfs_map_name_to_uid)(server, p, len, uid) != 0)
			goto out;
		dprintk("%s: uid=%d\n", __func__, (int)from_kuid(&init_user_ns, *uid));
		return NFS_ATTR_FATTR_OWNER;
	}
out:
	if (len != -EBADMSG)
		return 0;
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_group(struct xdr_stream *xdr, uint32_t *bitmap,
		const struct nfs_server *server, kgid_t *gid,
		struct nfs4_string *group_name)
{
	ssize_t len;
	char *p;

	*gid = make_kgid(&init_user_ns, -2);
	if (unlikely(bitmap[1] & (FATTR4_WORD1_OWNER_GROUP - 1U)))
		return -EIO;
	if (!(bitmap[1] & FATTR4_WORD1_OWNER_GROUP))
		return 0;
	bitmap[1] &= ~FATTR4_WORD1_OWNER_GROUP;

	if (group_name != NULL) {
		len = klpr_decode_nfs4_string(xdr, group_name, GFP_NOWAIT);
		if (len <= 0)
			goto out;
		dprintk("%s: name=%s\n", __func__, group_name->data);
		return NFS_ATTR_FATTR_GROUP_NAME;
	} else {
		len = klpr_xdr_stream_decode_opaque_inline(xdr, (void **)&p,
				XDR_MAX_NETOBJ);
		if (len <= 0 || (*klpe_nfs_map_group_to_gid)(server, p, len, gid) != 0)
			goto out;
		dprintk("%s: gid=%d\n", __func__, (int)from_kgid(&init_user_ns, *gid));
		return NFS_ATTR_FATTR_GROUP;
	}
out:
	if (len != -EBADMSG)
		return 0;
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_rdev(struct xdr_stream *xdr, uint32_t *bitmap, dev_t *rdev)
{
	uint32_t major = 0, minor = 0;
	__be32 *p;
	int ret = 0;

	*rdev = MKDEV(0,0);
	if (unlikely(bitmap[1] & (FATTR4_WORD1_RAWDEV - 1U)))
		return -EIO;
	if (likely(bitmap[1] & FATTR4_WORD1_RAWDEV)) {
		dev_t tmp;

		p = (*klpe_xdr_inline_decode)(xdr, 8);
		if (unlikely(!p))
			goto out_overflow;
		major = be32_to_cpup(p++);
		minor = be32_to_cpup(p);
		tmp = MKDEV(major, minor);
		if (MAJOR(tmp) == major && MINOR(tmp) == minor)
			*rdev = tmp;
		bitmap[1] &= ~ FATTR4_WORD1_RAWDEV;
		ret = NFS_ATTR_FATTR_RDEV;
	}
	dprintk("%s: rdev=(0x%x:0x%x)\n", __func__, major, minor);
	return ret;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_space_used(struct xdr_stream *xdr, uint32_t *bitmap, uint64_t *used)
{
	__be32 *p;
	int ret = 0;

	*used = 0;
	if (unlikely(bitmap[1] & (FATTR4_WORD1_SPACE_USED - 1U)))
		return -EIO;
	if (likely(bitmap[1] & FATTR4_WORD1_SPACE_USED)) {
		p = (*klpe_xdr_inline_decode)(xdr, 8);
		if (unlikely(!p))
			goto out_overflow;
		xdr_decode_hyper(p, used);
		bitmap[1] &= ~FATTR4_WORD1_SPACE_USED;
		ret = NFS_ATTR_FATTR_SPACE_USED;
	}
	dprintk("%s: space used=%Lu\n", __func__,
			(unsigned long long)*used);
	return ret;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int (*klpe_decode_attr_time)(struct xdr_stream *xdr, struct timespec *time);

static int klpr_decode_attr_time_access(struct xdr_stream *xdr, uint32_t *bitmap, struct timespec *time)
{
	int status = 0;

	time->tv_sec = 0;
	time->tv_nsec = 0;
	if (unlikely(bitmap[1] & (FATTR4_WORD1_TIME_ACCESS - 1U)))
		return -EIO;
	if (likely(bitmap[1] & FATTR4_WORD1_TIME_ACCESS)) {
		status = (*klpe_decode_attr_time)(xdr, time);
		if (status == 0)
			status = NFS_ATTR_FATTR_ATIME;
		bitmap[1] &= ~FATTR4_WORD1_TIME_ACCESS;
	}
	dprintk("%s: atime=%ld\n", __func__, (long)time->tv_sec);
	return status;
}

static int klpr_decode_attr_time_metadata(struct xdr_stream *xdr, uint32_t *bitmap, struct timespec *time)
{
	int status = 0;

	time->tv_sec = 0;
	time->tv_nsec = 0;
	if (unlikely(bitmap[1] & (FATTR4_WORD1_TIME_METADATA - 1U)))
		return -EIO;
	if (likely(bitmap[1] & FATTR4_WORD1_TIME_METADATA)) {
		status = (*klpe_decode_attr_time)(xdr, time);
		if (status == 0)
			status = NFS_ATTR_FATTR_CTIME;
		bitmap[1] &= ~FATTR4_WORD1_TIME_METADATA;
	}
	dprintk("%s: ctime=%ld\n", __func__, (long)time->tv_sec);
	return status;
}

static int klpp_decode_attr_security_label(struct xdr_stream *xdr, uint32_t *bitmap,
					struct nfs4_label *label)
{
	uint32_t pi = 0;
	uint32_t lfs = 0;
	__u32 len;
	__be32 *p;
	int status = 0;

	if (unlikely(bitmap[2] & (FATTR4_WORD2_SECURITY_LABEL - 1U)))
		return -EIO;
	if (likely(bitmap[2] & FATTR4_WORD2_SECURITY_LABEL)) {
		p = (*klpe_xdr_inline_decode)(xdr, 4);
		if (unlikely(!p))
			goto out_overflow;
		lfs = be32_to_cpup(p++);
		p = (*klpe_xdr_inline_decode)(xdr, 4);
		if (unlikely(!p))
			goto out_overflow;
		pi = be32_to_cpup(p++);
		p = (*klpe_xdr_inline_decode)(xdr, 4);
		if (unlikely(!p))
			goto out_overflow;
		len = be32_to_cpup(p++);
		p = (*klpe_xdr_inline_decode)(xdr, len);
		if (unlikely(!p))
			goto out_overflow;
		if (len < NFS4_MAXLABELLEN) {
			if (label) {
				/*
				 * Fix CVE-2020-25212
				 *  -1 line, +5 lines
				 */
				if (label->len) {
					if (label->len < len)
						return -ERANGE;
					memcpy(label->label, p, len);
				}
				label->len = len;
				label->pi = pi;
				label->lfs = lfs;
				status = NFS_ATTR_FATTR_V4_SECURITY_LABEL;
			}
			bitmap[2] &= ~FATTR4_WORD2_SECURITY_LABEL;
		} else
			printk(KERN_WARNING "%s: label too long (%u)!\n",
					__func__, len);
	}
	if (label && label->label)
		dprintk("%s: label=%s, len=%d, PI=%d, LFS=%d\n", __func__,
			(char *)label->label, label->len, label->pi, label->lfs);
	return status;

out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int klpr_decode_attr_time_modify(struct xdr_stream *xdr, uint32_t *bitmap, struct timespec *time)
{
	int status = 0;

	time->tv_sec = 0;
	time->tv_nsec = 0;
	if (unlikely(bitmap[1] & (FATTR4_WORD1_TIME_MODIFY - 1U)))
		return -EIO;
	if (likely(bitmap[1] & FATTR4_WORD1_TIME_MODIFY)) {
		status = (*klpe_decode_attr_time)(xdr, time);
		if (status == 0)
			status = NFS_ATTR_FATTR_MTIME;
		bitmap[1] &= ~FATTR4_WORD1_TIME_MODIFY;
	}
	dprintk("%s: mtime=%ld\n", __func__, (long)time->tv_sec);
	return status;
}

static int (*klpe_verify_attr_len)(struct xdr_stream *xdr, unsigned int savep, uint32_t attrlen);

static int (*klpe_decode_threshold_hint)(struct xdr_stream *xdr,
				  uint32_t *bitmap,
				  uint64_t *res,
				  uint32_t hint_bit);

static int klpr_decode_first_threshold_item4(struct xdr_stream *xdr,
					struct nfs4_threshold *res)
{
	__be32 *p;
	unsigned int savep;
	uint32_t bitmap[3] = {0,}, attrlen;
	int status;

	/* layout type */
	p = (*klpe_xdr_inline_decode)(xdr, 4);
	if (unlikely(!p)) {
		klpr_print_overflow_msg(__func__, xdr);
		return -EIO;
	}
	res->l_type = be32_to_cpup(p);

	/* thi_hintset bitmap */
	status = (*klpe_decode_attr_bitmap)(xdr, bitmap);
	if (status < 0)
		goto xdr_error;

	/* thi_hintlist length */
	status = (*klpe_decode_attr_length)(xdr, &attrlen, &savep);
	if (status < 0)
		goto xdr_error;
	/* thi_hintlist */
	status = (*klpe_decode_threshold_hint)(xdr, bitmap, &res->rd_sz, THRESHOLD_RD);
	if (status < 0)
		goto xdr_error;
	status = (*klpe_decode_threshold_hint)(xdr, bitmap, &res->wr_sz, THRESHOLD_WR);
	if (status < 0)
		goto xdr_error;
	status = (*klpe_decode_threshold_hint)(xdr, bitmap, &res->rd_io_sz,
				       THRESHOLD_RD_IO);
	if (status < 0)
		goto xdr_error;
	status = (*klpe_decode_threshold_hint)(xdr, bitmap, &res->wr_io_sz,
				       THRESHOLD_WR_IO);
	if (status < 0)
		goto xdr_error;

	status = (*klpe_verify_attr_len)(xdr, savep, attrlen);
	res->bm = bitmap[0];

	dprintk("%s bm=0x%x rd_sz=%llu wr_sz=%llu rd_io=%llu wr_io=%llu\n",
		 __func__, res->bm, res->rd_sz, res->wr_sz, res->rd_io_sz,
		res->wr_io_sz);
xdr_error:
	dprintk("%s ret=%d!\n", __func__, status);
	return status;
}

static int klpr_decode_attr_mdsthreshold(struct xdr_stream *xdr,
				    uint32_t *bitmap,
				    struct nfs4_threshold *res)
{
	__be32 *p;
	int status = 0;
	uint32_t num;

	if (unlikely(bitmap[2] & (FATTR4_WORD2_MDSTHRESHOLD - 1U)))
		return -EIO;
	if (bitmap[2] & FATTR4_WORD2_MDSTHRESHOLD) {
		/* Did the server return an unrequested attribute? */
		if (unlikely(res == NULL))
			return -EREMOTEIO;
		p = (*klpe_xdr_inline_decode)(xdr, 4);
		if (unlikely(!p))
			goto out_overflow;
		num = be32_to_cpup(p);
		if (num == 0)
			return 0;
		if (num > 1)
			printk(KERN_INFO "%s: Warning: Multiple pNFS layout "
				"drivers per filesystem not supported\n",
				__func__);

		status = klpr_decode_first_threshold_item4(xdr, res);
		bitmap[2] &= ~FATTR4_WORD2_MDSTHRESHOLD;
	}
	return status;
out_overflow:
	klpr_print_overflow_msg(__func__, xdr);
	return -EIO;
}

int klpp_decode_getfattr_attrs(struct xdr_stream *xdr, uint32_t *bitmap,
		struct nfs_fattr *fattr, struct nfs_fh *fh,
		struct nfs4_fs_locations *fs_loc, struct nfs4_label *label,
		const struct nfs_server *server)
{
	int status;
	umode_t fmode = 0;
	uint32_t type;
	int32_t err;

	status = klpr_decode_attr_type(xdr, bitmap, &type);
	if (status < 0)
		goto xdr_error;
	fattr->mode = 0;
	if (status != 0) {
		fattr->mode |= (*klpe_nfs_type2fmt)[type];
		fattr->valid |= status;
	}

	status = klpr_decode_attr_change(xdr, bitmap, &fattr->change_attr);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = klpr_decode_attr_size(xdr, bitmap, &fattr->size);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = klpr_decode_attr_fsid(xdr, bitmap, &fattr->fsid);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	err = 0;
	status = klpr_decode_attr_error(xdr, bitmap, &err);
	if (status < 0)
		goto xdr_error;

	status = klpr_decode_attr_filehandle(xdr, bitmap, fh);
	if (status < 0)
		goto xdr_error;

	status = klpr_decode_attr_fileid(xdr, bitmap, &fattr->fileid);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = klpr_decode_attr_fs_locations(xdr, bitmap, fs_loc);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = -EIO;
	if (unlikely(bitmap[0]))
		goto xdr_error;

	status = klpr_decode_attr_mode(xdr, bitmap, &fmode);
	if (status < 0)
		goto xdr_error;
	if (status != 0) {
		fattr->mode |= fmode;
		fattr->valid |= status;
	}

	status = klpr_decode_attr_nlink(xdr, bitmap, &fattr->nlink);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = klpr_decode_attr_owner(xdr, bitmap, server, &fattr->uid, fattr->owner_name);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = klpr_decode_attr_group(xdr, bitmap, server, &fattr->gid, fattr->group_name);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = klpr_decode_attr_rdev(xdr, bitmap, &fattr->rdev);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = klpr_decode_attr_space_used(xdr, bitmap, &fattr->du.nfs3.used);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = klpr_decode_attr_time_access(xdr, bitmap, &fattr->atime);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = klpr_decode_attr_time_metadata(xdr, bitmap, &fattr->ctime);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = klpr_decode_attr_time_modify(xdr, bitmap, &fattr->mtime);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = klpr_decode_attr_mounted_on_fileid(xdr, bitmap, &fattr->mounted_on_fileid);
	if (status < 0)
		goto xdr_error;
	fattr->valid |= status;

	status = -EIO;
	if (unlikely(bitmap[1]))
		goto xdr_error;

	status = klpr_decode_attr_mdsthreshold(xdr, bitmap, fattr->mdsthreshold);
	if (status < 0)
		goto xdr_error;

	if (label) {
		status = klpp_decode_attr_security_label(xdr, bitmap, label);
		if (status < 0)
			goto xdr_error;
		fattr->valid |= status;
	}

xdr_error:
	dprintk("%s: xdr returned %d\n", __func__, -status);
	return status;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfs_debug", (void *)&klpe_nfs_debug, "sunrpc" },
	{ "nfs_type2fmt", (void *)&klpe_nfs_type2fmt, "nfsv4" },
	{ "xdr_inline_decode", (void *)&klpe_xdr_inline_decode, "sunrpc" },
	{ "xdr_stream_decode_string_dup", (void *)&klpe_xdr_stream_decode_string_dup, "sunrpc" },
	{ "nfs_map_name_to_uid", (void *)&klpe_nfs_map_name_to_uid, "nfsv4" },
	{ "nfs_map_group_to_gid", (void *)&klpe_nfs_map_group_to_gid, "nfsv4" },
	{ "decode_opaque_inline", (void *)&klpe_decode_opaque_inline, "nfsv4" },
	{ "decode_attr_bitmap", (void *)&klpe_decode_attr_bitmap, "nfsv4" },
	{ "decode_attr_length", (void *)&klpe_decode_attr_length, "nfsv4" },
	{ "decode_pathname", (void *)&klpe_decode_pathname, "nfsv4" },
	{ "decode_attr_time", (void *)&klpe_decode_attr_time, "nfsv4" },
	{ "verify_attr_len", (void *)&klpe_verify_attr_len, "nfsv4" },
	{ "decode_threshold_hint", (void *)&klpe_decode_threshold_hint, "nfsv4" },
};

static int livepatch_bsc1176382_nfs4xdr_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1176382_nfs4xdr_module_nb = {
	.notifier_call = livepatch_bsc1176382_nfs4xdr_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1176382_nfs4xdr_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1176382_nfs4xdr_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1176382_nfs4xdr_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1176382_nfs4xdr_module_nb);
}
