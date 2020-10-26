/*
 * bsc1176382_dir
 *
 * Fix for CVE-2020-25212, bsc#1176382 (fs/nfs/dir.c part)
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

#if !IS_MODULE(CONFIG_NFS_FS)
#error "Live patch supports only CONFIG_NFS_FS=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1176382.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nfs"

/* klp-ccp: from fs/nfs/dir.c */
#include <linux/module.h>
#include <linux/time.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sunrpc/clnt.h>

/* klp-ccp: from include/linux/sunrpc/xdr.h */
static void (*klpe_xdr_init_decode_pages)(struct xdr_stream *xdr, struct xdr_buf *buf,
		struct page **pages, unsigned int len);
static void (*klpe_xdr_set_scratch_buffer)(struct xdr_stream *xdr, void *buf, size_t buflen);

/* klp-ccp: from fs/nfs/dir.c */
#include <linux/nfs_fs.h>

/* klp-ccp: from include/linux/nfs_fs.h */
static struct inode *(*klpe_nfs_fhget)(struct super_block *, struct nfs_fh *,
				struct nfs_fattr *, struct nfs4_label *);

static int (*klpe_nfs_refresh_inode)(struct inode *, struct nfs_fattr *);

static void (*klpe_nfs_setsecurity)(struct inode *inode, struct nfs_fattr *fattr,
				struct nfs4_label *label);

/* klp-ccp: from fs/nfs/dir.c */
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/kmemleak.h>
/* klp-ccp: from fs/nfs/iostat.h */
#include <linux/percpu.h>
#include <linux/cache.h>

/* klp-ccp: from fs/nfs/nfs4_fs.h */
#include <linux/seqlock.h>

/* klp-ccp: from fs/nfs/internal.h */
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/wait_bit.h>
/* klp-ccp: from fs/nfs/fscache.h */
#include <linux/nfs_fs.h>
#include <linux/nfs_mount.h>

/* klp-ccp: from fs/nfs/dir.c */
struct nfs_cache_array_entry {
	u64 cookie;
	u64 ino;
	struct qstr string;
	unsigned char d_type;
};

struct nfs_cache_array {
	int size;
	int eof_index;
	u64 last_cookie;
	struct nfs_cache_array_entry array[0];
};

typedef int (*decode_dirent_t)(struct xdr_stream *, struct nfs_entry *, bool);
typedef struct klpp_nfs_readdir_descriptor {
	struct file	*file;
	struct page	*page;
	struct dir_context *ctx;
	unsigned long	page_index;
	u64		*dir_cookie;
	u64		last_cookie;
	loff_t		current_index;
	decode_dirent_t	decode;

	unsigned long	timestamp;
	unsigned long	gencount;
	unsigned int	cache_entry_index;
	bool plus;
	bool eof;
} nfs_readdir_descriptor_t;

static
int nfs_readdir_make_qstr(struct qstr *string, const char *name, unsigned int len)
{
	string->len = len;
	string->name = kmemdup(name, len, GFP_KERNEL);
	if (string->name == NULL)
		return -ENOMEM;
	/*
	 * Avoid a kmemleak false positive. The pointer to the name is stored
	 * in a page cache page which kmemleak does not scan.
	 */
	kmemleak_not_leak(string->name);
	string->hash = full_name_hash(NULL, name, len);
	return 0;
}

static
int nfs_readdir_add_to_array(struct nfs_entry *entry, struct page *page)
{
	struct nfs_cache_array *array = kmap(page);
	struct nfs_cache_array_entry *cache_entry;
	int ret;

	cache_entry = &array->array[array->size];

	/* Check that this entry lies within the page bounds */
	ret = -ENOSPC;
	if ((char *)&cache_entry[1] - (char *)page_address(page) > PAGE_SIZE)
		goto out;

	cache_entry->cookie = entry->prev_cookie;
	cache_entry->ino = entry->ino;
	cache_entry->d_type = entry->d_type;
	ret = nfs_readdir_make_qstr(&cache_entry->string, entry->name, entry->len);
	if (ret)
		goto out;
	array->last_cookie = entry->cookie;
	array->size++;
	if (entry->eof != 0)
		array->eof_index = array->size;
out:
	kunmap(page);
	return ret;
}

static int xdr_decode(nfs_readdir_descriptor_t *desc,
		      struct nfs_entry *entry, struct xdr_stream *xdr)
{
	int error;

	error = desc->decode(xdr, entry, desc->plus);
	if (error)
		return error;
	entry->fattr->time_start = desc->timestamp;
	entry->fattr->gencount = desc->gencount;
	return 0;
}

static
int nfs_same_file(struct dentry *dentry, struct nfs_entry *entry)
{
	struct inode *inode;
	struct nfs_inode *nfsi;

	if (d_really_is_negative(dentry))
		return 0;

	inode = d_inode(dentry);
	if (is_bad_inode(inode) || NFS_STALE(inode))
		return 0;

	nfsi = NFS_I(inode);
	if (entry->fattr->fileid != nfsi->fileid)
		return 0;
	if (entry->fh->size && nfs_compare_fh(entry->fh, &nfsi->fh) != 0)
		return 0;
	return 1;
}

static
void klpr_nfs_prime_dcache(struct dentry *parent, struct nfs_entry *entry)
{
	struct qstr filename = QSTR_INIT(entry->name, entry->len);
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);
	struct dentry *dentry;
	struct dentry *alias;
	struct inode *dir = d_inode(parent);
	struct inode *inode;
	int status;

	if (!(entry->fattr->valid & NFS_ATTR_FATTR_FILEID))
		return;
	if (!(entry->fattr->valid & NFS_ATTR_FATTR_FSID))
		return;
	if (filename.len == 0)
		return;
	/* Validate that the name doesn't contain any illegal '\0' */
	if (strnlen(filename.name, filename.len) != filename.len)
		return;
	/* ...or '/' */
	if (strnchr(filename.name, filename.len, '/'))
		return;
	if (filename.name[0] == '.') {
		if (filename.len == 1)
			return;
		if (filename.len == 2 && filename.name[1] == '.')
			return;
	}
	filename.hash = full_name_hash(parent, filename.name, filename.len);

	dentry = d_lookup(parent, &filename);
again:
	if (!dentry) {
		dentry = d_alloc_parallel(parent, &filename, &wq);
		if (IS_ERR(dentry))
			return;
	}
	if (!d_in_lookup(dentry)) {
		/* Is there a mountpoint here? If so, just exit */
		if (!nfs_fsid_equal(&NFS_SB(dentry->d_sb)->fsid,
					&entry->fattr->fsid))
			goto out;
		if (nfs_same_file(dentry, entry)) {
			if (!entry->fh->size)
				goto out;
			nfs_set_verifier(dentry, nfs_save_change_attribute(dir));
			status = (*klpe_nfs_refresh_inode)(d_inode(dentry), entry->fattr);
			if (!status)
				(*klpe_nfs_setsecurity)(d_inode(dentry), entry->fattr, entry->label);
			goto out;
		} else {
			d_invalidate(dentry);
			dput(dentry);
			dentry = NULL;
			goto again;
		}
	}
	if (!entry->fh->size) {
		d_lookup_done(dentry);
		goto out;
	}

	inode = (*klpe_nfs_fhget)(dentry->d_sb, entry->fh, entry->fattr, entry->label);
	alias = d_splice_alias(inode, dentry);
	d_lookup_done(dentry);
	if (alias) {
		if (IS_ERR(alias))
			goto out;
		dput(dentry);
		dentry = alias;
	}
	nfs_set_verifier(dentry, nfs_save_change_attribute(dir));
out:
	dput(dentry);
}

int klpp_nfs_readdir_page_filler(nfs_readdir_descriptor_t *desc, struct nfs_entry *entry,
				struct page **xdr_pages, struct page *page, unsigned int buflen)
{
	struct xdr_stream stream;
	struct xdr_buf buf;
	struct page *scratch;
	struct nfs_cache_array *array;
	unsigned int count = 0;
	int status;

	scratch = alloc_page(GFP_KERNEL);
	if (scratch == NULL)
		return -ENOMEM;

	if (buflen == 0)
		goto out_nopages;

	(*klpe_xdr_init_decode_pages)(&stream, &buf, xdr_pages, buflen);
	(*klpe_xdr_set_scratch_buffer)(&stream, page_address(scratch), PAGE_SIZE);

	do {
		/*
		 * Fix CVE-2020-25212
		 *  +3 lines
		 */
		if (entry->label)
			entry->label->len = NFS4_MAXLABELLEN;

		status = xdr_decode(desc, entry, &stream);
		if (status != 0) {
			if (status == -EAGAIN)
				status = 0;
			break;
		}

		count++;

		if (desc->plus)
			klpr_nfs_prime_dcache(file_dentry(desc->file), entry);

		status = nfs_readdir_add_to_array(entry, page);
		if (status != 0)
			break;
	} while (!entry->eof);

out_nopages:
	if (count == 0 || (status == -EBADCOOKIE && entry->eof != 0)) {
		array = kmap(page);
		array->eof_index = array->size;
		status = 0;
		kunmap(page);
	}

	put_page(scratch);
	return status;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "xdr_init_decode_pages", (void *)&klpe_xdr_init_decode_pages,
	  "sunrpc" },
	{ "xdr_set_scratch_buffer", (void *)&klpe_xdr_set_scratch_buffer,
	  "sunrpc" },
	{ "nfs_fhget", (void *)&klpe_nfs_fhget, "nfs" },
	{ "nfs_refresh_inode", (void *)&klpe_nfs_refresh_inode, "nfs" },
	{ "nfs_setsecurity", (void *)&klpe_nfs_setsecurity, "nfs" },
};

static int livepatch_bsc1176382_dir_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1176382_dir_module_nb = {
	.notifier_call = livepatch_bsc1176382_dir_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1176382_dir_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1176382_dir_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1176382_dir_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1176382_dir_module_nb);
}
