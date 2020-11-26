/*
 * livepatch_bsc1178700
 *
 * Fix for CVE-2020-8694, bsc#1178700
 *
 *  Upstream commit:
 *  949dd0104c49 ("powercap: restrict energy meter to root access")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  ebf14284e7069d0ddb45df5e5c5bf8ebe016ed05
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  addf7037ac3a8534b4f090b2decab89672906666
 *
 *  SLE15-SP2 commit:
 *  4deb70ffd558a4926cd7bca5cb8dd81c000583b1
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

#if IS_ENABLED(CONFIG_POWERCAP)

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1178700.h"
#include "../kallsyms_relocs.h"

/* klp-ccp: from fs/kernfs/file.c */
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/pagemap.h>
#include <linux/fsnotify.h>
/* klp-ccp: from fs/kernfs/kernfs-internal.h */
#include <linux/lockdep.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/kernfs.h>

static inline struct kernfs_root *kernfs_root(struct kernfs_node *kn)
{
	/* if parent exists, it's always a dir; otherwise, @sd is a dir */
	if (kn->parent)
		kn = kn->parent;
	return kn->dir.root;
}

static struct kernfs_node *(*klpe_kernfs_get_active)(struct kernfs_node *kn);
static void (*klpe_kernfs_put_active)(struct kernfs_node *kn);

/* klp-ccp: from fs/sysfs/file.c */
static const struct sysfs_ops *sysfs_file_ops(struct kernfs_node *kn)
{
	struct kobject *kobj = kn->parent->priv;

	if (kn->flags & KERNFS_LOCKDEP)
		lockdep_assert_held(kn);
	return kobj->ktype ? kobj->ktype->sysfs_ops : NULL;
}

static const struct kernfs_ops (*klpe_sysfs_file_kfops_rw);

/* klp-ccp: from drivers/base/core.c */
#define to_dev_attr(_attr) container_of(_attr, struct device_attribute, attr)

static const struct sysfs_ops (*klpe_dev_sysfs_ops);

/* klp-ccp: from drivers/powercap/powercap_sys.c */
static ssize_t (*klpe_energy_uj_show)(struct device *dev,
			      struct device_attribute *dev_attr,
			      char *buf);

/* klp-ccp: from fs/kernfs/file.c */
static spinlock_t (*klpe_kernfs_open_node_lock);
static struct mutex (*klpe_kernfs_open_file_mutex);

struct kernfs_open_node {
	atomic_t		refcnt;
	atomic_t		event;
	wait_queue_head_t	poll;
	struct list_head	files; /* goes through kernfs_open_file.list */
};

static const struct kernfs_ops *kernfs_ops(struct kernfs_node *kn)
{
	if (kn->flags & KERNFS_LOCKDEP)
		lockdep_assert_held(kn);
	return kn->attr.ops;
}

static const struct seq_operations (*klpe_kernfs_seq_ops);

static int klpr_kernfs_get_open_node(struct kernfs_node *kn,
				struct kernfs_open_file *of)
{
	struct kernfs_open_node *on, *new_on = NULL;

 retry:
	mutex_lock(&(*klpe_kernfs_open_file_mutex));
	spin_lock_irq(&(*klpe_kernfs_open_node_lock));

	if (!kn->attr.open && new_on) {
		kn->attr.open = new_on;
		new_on = NULL;
	}

	on = kn->attr.open;
	if (on) {
		atomic_inc(&on->refcnt);
		list_add_tail(&of->list, &on->files);
	}

	spin_unlock_irq(&(*klpe_kernfs_open_node_lock));
	mutex_unlock(&(*klpe_kernfs_open_file_mutex));

	if (on) {
		kfree(new_on);
		return 0;
	}

	/* not there, initialize a new one and retry */
	new_on = kmalloc(sizeof(*new_on), GFP_KERNEL);
	if (!new_on)
		return -ENOMEM;

	atomic_set(&new_on->refcnt, 0);
	atomic_set(&new_on->event, 1);
	init_waitqueue_head(&new_on->poll);
	INIT_LIST_HEAD(&new_on->files);
	goto retry;
}

static void klpr_kernfs_put_open_node(struct kernfs_node *kn,
				 struct kernfs_open_file *of)
{
	struct kernfs_open_node *on = kn->attr.open;
	unsigned long flags;

	mutex_lock(&(*klpe_kernfs_open_file_mutex));
	spin_lock_irqsave(&(*klpe_kernfs_open_node_lock), flags);

	if (of)
		list_del(&of->list);

	if (atomic_dec_and_test(&on->refcnt))
		kn->attr.open = NULL;
	else
		on = NULL;

	spin_unlock_irqrestore(&(*klpe_kernfs_open_node_lock), flags);
	mutex_unlock(&(*klpe_kernfs_open_file_mutex));

	kfree(on);
}

int klpp_kernfs_fop_open(struct inode *inode, struct file *file)
{
	struct kernfs_node *kn = inode->i_private;
	struct kernfs_root *root = kernfs_root(kn);
	const struct kernfs_ops *ops;
	struct kernfs_open_file *of;
	bool has_read, has_write, has_mmap;
	int error = -EACCES;

	if (!(*klpe_kernfs_get_active)(kn))
		return -ENODEV;

	ops = kernfs_ops(kn);

	/*
	 * Fix CVE-2020-8694
	 *  +12 lines
	 */
	if (ops == &(*klpe_sysfs_file_kfops_rw) &&
	    sysfs_file_ops(kn) == &(*klpe_dev_sysfs_ops) &&
	    kn->priv && /* Not needed, only be conservative */
	    (to_dev_attr((struct attribute *)kn->priv)->show ==
	     (*klpe_energy_uj_show))) {
		/*
		 * Alright, it's powercap's energy_uj file. Enforce
		 * S_IRUSR.
		 */
		if (!uid_eq(current_fsuid(), inode->i_uid))
			goto err_out;
	}

	has_read = ops->seq_show || ops->read || ops->mmap;
	has_write = ops->write || ops->mmap;
	has_mmap = ops->mmap;

	/* see the flag definition for details */
	if (root->flags & KERNFS_ROOT_EXTRA_OPEN_PERM_CHECK) {
		if ((file->f_mode & FMODE_WRITE) &&
		    (!(inode->i_mode & S_IWUGO) || !has_write))
			goto err_out;

		if ((file->f_mode & FMODE_READ) &&
		    (!(inode->i_mode & S_IRUGO) || !has_read))
			goto err_out;
	}

	/* allocate a kernfs_open_file for the file */
	error = -ENOMEM;
	of = kzalloc(sizeof(struct kernfs_open_file), GFP_KERNEL);
	if (!of)
		goto err_out;

	/*
	 * The following is done to give a different lockdep key to
	 * @of->mutex for files which implement mmap.  This is a rather
	 * crude way to avoid false positive lockdep warning around
	 * mm->mmap_sem - mmap nests @of->mutex under mm->mmap_sem and
	 * reading /sys/block/sda/trace/act_mask grabs sr_mutex, under
	 * which mm->mmap_sem nests, while holding @of->mutex.  As each
	 * open file has a separate mutex, it's okay as long as those don't
	 * happen on the same file.  At this point, we can't easily give
	 * each file a separate locking class.  Let's differentiate on
	 * whether the file has mmap or not for now.
	 *
	 * Both paths of the branch look the same.  They're supposed to
	 * look that way and give @of->mutex different static lockdep keys.
	 */
	if (has_mmap)
		mutex_init(&of->mutex);
	else
		mutex_init(&of->mutex);

	of->kn = kn;
	of->file = file;

	/*
	 * Write path needs to atomic_write_len outside active reference.
	 * Cache it in open_file.  See kernfs_fop_write() for details.
	 */
	of->atomic_write_len = ops->atomic_write_len;

	error = -EINVAL;
	/*
	 * ->seq_show is incompatible with ->prealloc,
	 * as seq_read does its own allocation.
	 * ->read must be used instead.
	 */
	if (ops->prealloc && ops->seq_show)
		goto err_free;
	if (ops->prealloc) {
		int len = of->atomic_write_len ?: PAGE_SIZE;
		of->prealloc_buf = kmalloc(len + 1, GFP_KERNEL);
		error = -ENOMEM;
		if (!of->prealloc_buf)
			goto err_free;
		mutex_init(&of->prealloc_mutex);
	}

	/*
	 * Always instantiate seq_file even if read access doesn't use
	 * seq_file or is not requested.  This unifies private data access
	 * and readable regular files are the vast majority anyway.
	 */
	if (ops->seq_show)
		error = seq_open(file, &(*klpe_kernfs_seq_ops));
	else
		error = seq_open(file, NULL);
	if (error)
		goto err_free;

	of->seq_file = file->private_data;
	of->seq_file->private = of;

	/* seq_file clears PWRITE unconditionally, restore it if WRITE */
	if (file->f_mode & FMODE_WRITE)
		file->f_mode |= FMODE_PWRITE;

	/* make sure we have open node struct */
	error = klpr_kernfs_get_open_node(kn, of);
	if (error)
		goto err_seq_release;

	if (ops->open) {
		/* nobody has access to @of yet, skip @of->mutex */
		error = ops->open(of);
		if (error)
			goto err_put_node;
	}

	/* open succeeded, put active references */
	(*klpe_kernfs_put_active)(kn);
	return 0;

err_put_node:
	klpr_kernfs_put_open_node(kn, of);
err_seq_release:
	seq_release(inode, file);
err_free:
	kfree(of->prealloc_buf);
	kfree(of);
err_out:
	(*klpe_kernfs_put_active)(kn);
	return error;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "kernfs_open_node_lock", (void *)&klpe_kernfs_open_node_lock },
	{ "kernfs_open_file_mutex", (void *)&klpe_kernfs_open_file_mutex },
	{ "kernfs_seq_ops", (void *)&klpe_kernfs_seq_ops },
	{ "kernfs_get_active", (void *)&klpe_kernfs_get_active },
	{ "kernfs_put_active", (void *)&klpe_kernfs_put_active },
	{ "sysfs_file_kfops_rw", (void *)&klpe_sysfs_file_kfops_rw },
	{ "dev_sysfs_ops", (void *)&klpe_dev_sysfs_ops },
	{ "energy_uj_show", (void *)&klpe_energy_uj_show },
};

int livepatch_bsc1178700_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_POWERCAP) */
