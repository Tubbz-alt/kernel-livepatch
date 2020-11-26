/*
 * livepatch_bsc1178046
 *
 * Fix for bsc#1178046
 *
 *  Upstream commits:
 *  0c9ab349c205 ("btrfs: flush_space always takes fs_info->fs_root")
 *  a9b3311ef36b ("btrfs: fix race with relocation recovery and fs_root setup")
 *  1b86826d12dc ("btrfs: cleanup root usage by btrfs_get_alloc_profile")
 *  c1c4919b112d ("btrfs: remove root usage from can_overcommit")
 *
 *  SLE12-SP2 commits:
 *  75e2fd323ff14d51565c49ffc54d74a3e107ab1d
 *  296894b76e9bfd237f98aced2104c88ee9fbd654
 *  ee8b454b9e4b2d1d045613f3fd7fd30495a1ac50
 *
 *  SLE12-SP3 commit:
 *  not affected
 *
 *  SLE12-SP4 commits:
 *  95e125e5a8d2617b1edd42dddeabbdddb723207b
 *  492e6bd7325c6a0d148d34bb770b6aefc9349c3a
 *
 *  SLE15 commits:
 *  none yet
 *
 *  SLE12-SP5 and SLE15-SP1 commits:
 *  95e125e5a8d2617b1edd42dddeabbdddb723207b
 *  09d9f20ac595ab493fe78f206e296ef409e7e910
 *
 *  SLE15-SP2 commit:
 *  not affected
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

#if !IS_MODULE(CONFIG_BTRFS_FS)
#error "Live patch supports only CONFIG_BTRFS_FS=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1178046.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "btrfs"

/* klp-ccp: from fs/btrfs/ctree.h */
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/rwsem.h>
#include <linux/semaphore.h>
#include <linux/completion.h>
#include <linux/backing-dev.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/kobject.h>

/* klp-ccp: from include/trace/events/btrfs.h */
struct btrfs_work;

#define BTRFS_UUID_SIZE 16

/* klp-ccp: from fs/btrfs/ctree.h */
#include <asm/kmap_types.h>
#include <linux/pagemap.h>
#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/sizes.h>
#include <linux/dynamic_debug.h>
#include <linux/refcount.h>
/* klp-ccp: from fs/btrfs/extent_io.h */
#include <linux/rbtree.h>
#include <linux/refcount.h>
/* klp-ccp: from fs/btrfs/ulist.h */
#include <linux/list.h>
#include <linux/rbtree.h>

/* klp-ccp: from fs/btrfs/extent_io.h */
struct extent_io_tree {
	struct rb_root state;
	struct address_space *mapping;
	u64 dirty_bytes;
	int track_uptodate;
	spinlock_t lock;
	const struct extent_io_ops *ops;
};

/* klp-ccp: from fs/btrfs/extent_map.h */
#include <linux/rbtree.h>
#include <linux/refcount.h>

struct extent_map_tree {
	struct rb_root map;
	struct list_head modified_extents;
	rwlock_t lock;
};

/* klp-ccp: from fs/btrfs/async-thread.h */
#include <linux/workqueue.h>

typedef void (*btrfs_func_t)(struct btrfs_work *arg);

struct btrfs_work {
	btrfs_func_t func;
	btrfs_func_t ordered_func;
	btrfs_func_t ordered_free;

	/* Don't touch things below */
	struct work_struct normal_work;
	struct list_head ordered_list;
	struct __btrfs_workqueue *wq;
	unsigned long flags;
};

/* klp-ccp: from fs/btrfs/block-rsv.h */
struct btrfs_block_rsv {
	u64 size;
	u64 reserved;
	struct btrfs_space_info *space_info;
	spinlock_t lock;
	unsigned short full;
	unsigned short type;
	unsigned short failfast;

	/*
	 * Qgroup equivalent for @size @reserved
	 *
	 * Unlike normal @size/@reserved for inode rsv, qgroup doesn't care
	 * about things like csum size nor how many tree blocks it will need to
	 * reserve.
	 *
	 * Qgroup cares more about net change of the extent usage.
	 *
	 * So for one newly inserted file extent, in worst case it will cause
	 * leaf split and level increase, nodesize for each file extent is
	 * already too much.
	 *
	 * In short, qgroup_size/reserved is the upper limit of possible needed
	 * qgroup metadata reservation.
	 */
	u64 qgroup_rsv_size;
	u64 qgroup_rsv_reserved;
};

/* klp-ccp: from fs/btrfs/ctree.h */
#define BTRFS_MAX_LEVEL 8

struct btrfs_mapping_tree {
	struct extent_map_tree map_tree;
};

struct btrfs_dev_replace {
	u64 replace_state;	/* see #define above */
	u64 time_started;	/* seconds since 1-Jan-1970 */
	u64 time_stopped;	/* seconds since 1-Jan-1970 */
	atomic64_t num_write_errors;
	atomic64_t num_uncorrectable_read_errors;

	u64 cursor_left;
	u64 committed_cursor_left;
	u64 cursor_left_last_write_of_item;
	u64 cursor_right;

	u64 cont_reading_from_srcdev_mode;	/* see #define above */

	int is_valid;
	int item_needs_writeback;
	struct btrfs_device *srcdev;
	struct btrfs_device *tgtdev;

	pid_t lock_owner;
	atomic_t nesting_level;
	struct mutex lock_finishing_cancel_unmount;
	rwlock_t lock;
	atomic_t read_locks;
	atomic_t blocking_readers;
	wait_queue_head_t read_lock_wq;

	struct btrfs_scrub_progress scrub_progress;
};

struct btrfs_free_cluster {
	spinlock_t lock;
	spinlock_t refill_lock;
	struct rb_root root;

	/* largest extent in this cluster */
	u64 max_size;

	/* first extent starting offset */
	u64 window_start;

	/* We did a full search and couldn't create a cluster */
	bool fragmented;

	struct btrfs_block_group_cache *block_group;
	/*
	 * when a cluster is allocated from a block group, we put the
	 * cluster onto a list in the block group so that it can
	 * be freed before the block group is freed.
	 */
	struct list_head block_group_list;
};

enum btrfs_caching_type {
	BTRFS_CACHE_NO		= 0,
	BTRFS_CACHE_STARTED	= 1,
	BTRFS_CACHE_FAST	= 2,
	BTRFS_CACHE_FINISHED	= 3,
	BTRFS_CACHE_ERROR	= 4,
};

struct btrfs_fs_info {
	u8 chunk_tree_uuid[BTRFS_UUID_SIZE];
	unsigned long flags;
	struct btrfs_root *extent_root;
	struct btrfs_root *tree_root;
	struct btrfs_root *chunk_root;
	struct btrfs_root *dev_root;
	struct btrfs_root *fs_root;
	struct btrfs_root *csum_root;
	struct btrfs_root *quota_root;
	struct btrfs_root *uuid_root;
	struct btrfs_root *free_space_root;

	/* the log root tree is a directory of all the other log roots */
	struct btrfs_root *log_root_tree;

	spinlock_t fs_roots_radix_lock;
	struct radix_tree_root fs_roots_radix;

	/* block group cache stuff */
	spinlock_t block_group_cache_lock;
	u64 first_logical_byte;
	struct rb_root block_group_cache_tree;

	/* keep track of unallocated space */
	spinlock_t free_chunk_lock;
	u64 free_chunk_space;

	struct extent_io_tree freed_extents[2];
	struct extent_io_tree *pinned_extents;

	/* logical->physical extent mapping */
	struct btrfs_mapping_tree mapping_tree;

	/*
	 * block reservation for extent, checksum, root tree and
	 * delayed dir index item
	 */
	struct btrfs_block_rsv global_block_rsv;
	/* block reservation for metadata operations */
	struct btrfs_block_rsv trans_block_rsv;
	/* block reservation for chunk tree */
	struct btrfs_block_rsv chunk_block_rsv;
	/* block reservation for delayed operations */
	struct btrfs_block_rsv delayed_block_rsv;
	/* block reservation for delayed refs */
	struct btrfs_block_rsv delayed_refs_rsv;

	struct btrfs_block_rsv empty_block_rsv;

	u64 generation;
	u64 last_trans_committed;
	u64 avg_delayed_ref_runtime;

	/*
	 * this is updated to the current trans every time a full commit
	 * is required instead of the faster short fsync log commits
	 */
	u64 last_trans_log_full_commit;
	unsigned long mount_opt;
	/*
	 * Track requests for actions that need to be done during transaction
	 * commit (like for some mount options).
	 */
	unsigned long pending_changes;
	unsigned long compress_type:4;
	int commit_interval;
	/*
	 * It is a suggestive number, the read side is safe even it gets a
	 * wrong number because we will write out the data into a regular
	 * extent. The write side(mount/remount) is under ->s_umount lock,
	 * so it is also safe.
	 */
	u64 max_inline;
	/*
	 * Protected by ->chunk_mutex and sb->s_umount.
	 *
	 * The reason that we use two lock to protect it is because only
	 * remount and mount operations can change it and these two operations
	 * are under sb->s_umount, but the read side (chunk allocation) can not
	 * acquire sb->s_umount or the deadlock would happen. So we use two
	 * locks to protect it. On the write side, we must acquire two locks,
	 * and on the read side, we just need acquire one of them.
	 */
	u64 alloc_start;
	struct btrfs_transaction *running_transaction;
	wait_queue_head_t transaction_throttle;
	wait_queue_head_t transaction_wait;
	wait_queue_head_t transaction_blocked_wait;
	wait_queue_head_t async_submit_wait;

	/*
	 * Used to protect the incompat_flags, compat_flags, compat_ro_flags
	 * when they are updated.
	 *
	 * Because we do not clear the flags for ever, so we needn't use
	 * the lock on the read side.
	 *
	 * We also needn't use the lock when we mount the fs, because
	 * there is no other task which will update the flag.
	 */
	spinlock_t super_lock;
	struct btrfs_super_block *super_copy;
	struct btrfs_super_block *super_for_commit;
	struct super_block *sb;
	struct inode *btree_inode;
	struct mutex tree_log_mutex;
	struct mutex transaction_kthread_mutex;
	struct mutex cleaner_mutex;
	struct mutex chunk_mutex;
	struct mutex volume_mutex;

	/*
	 * this is taken to make sure we don't set block groups ro after
	 * the free space cache has been allocated on them
	 */
	struct mutex ro_block_group_mutex;

	/* this is used during read/modify/write to make sure
	 * no two ios are trying to mod the same stripe at the same
	 * time
	 */
	struct btrfs_stripe_hash_table *stripe_hash_table;

	/*
	 * this protects the ordered operations list only while we are
	 * processing all of the entries on it.  This way we make
	 * sure the commit code doesn't find the list temporarily empty
	 * because another function happens to be doing non-waiting preflush
	 * before jumping into the main commit.
	 */
	struct mutex ordered_operations_mutex;

	struct rw_semaphore commit_root_sem;

	struct rw_semaphore cleanup_work_sem;

	struct rw_semaphore subvol_sem;
	struct srcu_struct subvol_srcu;

	spinlock_t trans_lock;
	/*
	 * the reloc mutex goes with the trans lock, it is taken
	 * during commit to protect us from the relocation code
	 */
	struct mutex reloc_mutex;

	struct list_head trans_list;
	struct list_head dead_roots;
	spinlock_t caching_block_groups_lock;
	struct list_head caching_block_groups;

	spinlock_t delayed_iput_lock;
	struct list_head delayed_iputs;
	atomic_t nr_delayed_iputs;
	wait_queue_head_t delayed_iputs_wait;

	atomic64_t tree_mod_seq;

	/* this protects tree_mod_log and tree_mod_seq_list */
	rwlock_t tree_mod_log_lock;
	struct rb_root tree_mod_log;
	struct list_head tree_mod_seq_list;

	atomic_t nr_async_submits;
	atomic_t async_submit_draining;
	atomic_t nr_async_bios;
	atomic_t async_delalloc_pages;
	atomic_t open_ioctl_trans;

	/*
	 * this is used to protect the following list -- ordered_roots.
	 */
	spinlock_t ordered_root_lock;

	/*
	 * all fs/file tree roots in which there are data=ordered extents
	 * pending writeback are added into this list.
	 *
	 * these can span multiple transactions and basically include
	 * every dirty data page that isn't from nodatacow
	 */
	struct list_head ordered_roots;

	struct mutex delalloc_root_mutex;
	spinlock_t delalloc_root_lock;
	/* all fs/file tree roots that have delalloc inodes. */
	struct list_head delalloc_roots;

	/*
	 * there is a pool of worker threads for checksumming during writes
	 * and a pool for checksumming after reads.  This is because readers
	 * can run with FS locks held, and the writers may be waiting for
	 * those locks.  We don't want ordering in the pending list to cause
	 * deadlocks, and so the two are serviced separately.
	 *
	 * A third pool does submit_bio to avoid deadlocking with the other
	 * two
	 */
	struct btrfs_workqueue *workers;
	struct btrfs_workqueue *delalloc_workers;
	struct btrfs_workqueue *flush_workers;
	struct btrfs_workqueue *endio_workers;
	struct btrfs_workqueue *endio_meta_workers;
	struct btrfs_workqueue *endio_raid56_workers;
	struct btrfs_workqueue *endio_repair_workers;
	struct btrfs_workqueue *rmw_workers;
	struct btrfs_workqueue *endio_meta_write_workers;
	struct btrfs_workqueue *endio_write_workers;
	struct btrfs_workqueue *endio_freespace_worker;
	struct btrfs_workqueue *submit_workers;
	struct btrfs_workqueue *caching_workers;
	struct btrfs_workqueue *readahead_workers;

	/*
	 * fixup workers take dirty pages that didn't properly go through
	 * the cow mechanism and make them safe to write.  It happens
	 * for the sys_munmap function call path
	 */
	struct btrfs_workqueue *fixup_workers;
	struct btrfs_workqueue *delayed_workers;

	/* the extent workers do delayed refs on the extent allocation tree */
	struct btrfs_workqueue *extent_workers;
	struct task_struct *transaction_kthread;
	struct task_struct *cleaner_kthread;
	int thread_pool_size;

	struct kobject *space_info_kobj;
	struct list_head pending_raid_kobjs;
	spinlock_t pending_raid_kobjs_lock; /* uncontended */

	u64 total_pinned;

	/* used to keep from writing metadata until there is a nice batch */
	struct percpu_counter dirty_metadata_bytes;
	struct percpu_counter delalloc_bytes;
	struct percpu_counter dio_bytes;
	s32 dirty_metadata_batch;
	s32 delalloc_batch;

	struct list_head dirty_cowonly_roots;

	struct btrfs_fs_devices *fs_devices;

	/*
	 * The space_info list is effectively read only after initial
	 * setup.  It is populated at mount time and cleaned up after
	 * all block groups are removed.  RCU is used to protect it.
	 */
	struct list_head space_info;

	struct btrfs_space_info *data_sinfo;

	struct reloc_control *reloc_ctl;

	/* data_alloc_cluster is only used in ssd mode */
	struct btrfs_free_cluster data_alloc_cluster;

	/* all metadata allocations go through this cluster */
	struct btrfs_free_cluster meta_alloc_cluster;

	/* auto defrag inodes go here */
	spinlock_t defrag_inodes_lock;
	struct rb_root defrag_inodes;
	atomic_t defrag_running;

	/* Used to protect avail_{data, metadata, system}_alloc_bits */
	seqlock_t profiles_lock;
	/*
	 * these three are in extended format (availability of single
	 * chunks is denoted by BTRFS_AVAIL_ALLOC_BIT_SINGLE bit, other
	 * types are denoted by corresponding BTRFS_BLOCK_GROUP_* bits)
	 */
	u64 avail_data_alloc_bits;
	u64 avail_metadata_alloc_bits;
	u64 avail_system_alloc_bits;

	/* restriper state */
	spinlock_t balance_lock;
	struct mutex balance_mutex;
	atomic_t balance_pause_req;
	atomic_t balance_cancel_req;
	struct btrfs_balance_control *balance_ctl;
	wait_queue_head_t balance_wait_q;

	unsigned data_chunk_allocations;
	unsigned metadata_ratio;

	void *bdev_holder;

	/* private scrub information */
	struct mutex scrub_lock;
	atomic_t scrubs_running;
	atomic_t scrub_pause_req;
	atomic_t scrubs_paused;
	atomic_t scrub_cancel_req;
	wait_queue_head_t scrub_pause_wait;
	int scrub_workers_refcnt;
	struct btrfs_workqueue *scrub_workers;
	struct btrfs_workqueue *scrub_wr_completion_workers;
	struct btrfs_workqueue *scrub_nocow_workers;
	struct btrfs_workqueue *scrub_parity_workers;

#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
#error "klp-ccp: non-taken branch"
#endif
	u64 qgroup_flags;

	/* holds configuration and tracking. Protected by qgroup_lock */
	struct rb_root qgroup_tree;
	struct rb_root qgroup_op_tree;
	spinlock_t qgroup_lock;
	spinlock_t qgroup_op_lock;
	atomic_t qgroup_op_seq;

	/*
	 * used to avoid frequently calling ulist_alloc()/ulist_free()
	 * when doing qgroup accounting, it must be protected by qgroup_lock.
	 */
	struct ulist *qgroup_ulist;

	/* protect user change for quota operations */
	struct mutex qgroup_ioctl_lock;

	/* list of dirty qgroups to be written at next commit */
	struct list_head dirty_qgroups;

	/* used by qgroup for an efficient tree traversal */
	u64 qgroup_seq;

	/* qgroup rescan items */
	struct mutex qgroup_rescan_lock; /* protects the progress item */
	struct btrfs_key qgroup_rescan_progress;
	struct btrfs_workqueue *qgroup_rescan_workers;
	struct completion qgroup_rescan_completion;
	struct btrfs_work qgroup_rescan_work;
	/* qgroup rescan worker is running or queued to run */
	bool qgroup_rescan_ready;
	bool qgroup_rescan_running;	/* protected by qgroup_rescan_lock */

	/* filesystem state */
	unsigned long fs_state;

	struct btrfs_delayed_root *delayed_root;

	/* readahead tree */
	spinlock_t reada_lock;
	struct radix_tree_root reada_tree;

	/* readahead works cnt */
	atomic_t reada_works_cnt;

	/* Extent buffer radix tree */
	spinlock_t buffer_lock;
	struct radix_tree_root buffer_radix;

	/* next backup root to be overwritten */
	int backup_root_index;

	int num_tolerated_disk_barrier_failures;

	/* device replace state */
	struct btrfs_dev_replace dev_replace;

	struct percpu_counter bio_counter;
	wait_queue_head_t replace_wait;

	struct semaphore uuid_tree_rescan_sem;

	/* Used to reclaim the metadata space in the background. */
	struct work_struct async_reclaim_work;

	spinlock_t unused_bgs_lock;
	struct list_head unused_bgs;
	struct mutex unused_bg_unpin_mutex;
	struct mutex delete_unused_bgs_mutex;

	/* For btrfs to record security options */
	struct security_mnt_opts security_opts;

	/*
	 * Chunks that can't be freed yet (under a trim/discard operation)
	 * and will be latter freed. Protected by fs_info->chunk_mutex.
	 */
	struct list_head pinned_chunks;

	/* Used to record internally whether fs has been frozen */
	int fs_frozen;

	/* Cached block sizes */
	u32 nodesize;
	u32 sectorsize;
	u32 stripesize;

	/*
	 * Number of send operations in progress.
	 * Updated while holding fs_info::balance_mutex.
	 */
	int send_in_progress;

	/* Block groups and devices containing active swapfiles. */
	spinlock_t swapfile_pins_lock;
	struct rb_root swapfile_pins;
};

struct btrfs_qgroup_swapped_blocks {
	spinlock_t lock;
	/* RM_EMPTY_ROOT() of above blocks[] */
	bool swapped;
	struct rb_root blocks[BTRFS_MAX_LEVEL];
};

struct btrfs_root {
	struct extent_buffer *node;

	struct extent_buffer *commit_root;
	struct btrfs_root *log_root;
	struct btrfs_root *reloc_root;

	unsigned long state;
	struct btrfs_root_item root_item;
	struct btrfs_key root_key;
	struct btrfs_fs_info *fs_info;
	struct extent_io_tree dirty_log_pages;

	struct mutex objectid_mutex;

	spinlock_t accounting_lock;
	struct btrfs_block_rsv *block_rsv;

	/* free ino cache stuff */
	struct btrfs_free_space_ctl *free_ino_ctl;
	enum btrfs_caching_type ino_cache_state;
	spinlock_t ino_cache_lock;
	wait_queue_head_t ino_cache_wait;
	struct btrfs_free_space_ctl *free_ino_pinned;
	u64 ino_cache_progress;
	struct inode *ino_cache_inode;

	struct mutex log_mutex;
	wait_queue_head_t log_writer_wait;
	wait_queue_head_t log_commit_wait[2];
	struct list_head log_ctxs[2];
	atomic_t log_writers;
	atomic_t log_commit[2];
	atomic_t log_batch;
	int log_transid;
	/* No matter the commit succeeds or not*/
	int log_transid_committed;
	/* Just be updated when the commit succeeds. */
	int last_log_commit;
	pid_t log_start_pid;

	u64 objectid;
	u64 last_trans;

	u32 type;

	u64 highest_objectid;

	/* Record pairs of swapped blocks for qgroup */
	struct btrfs_qgroup_swapped_blocks swapped_blocks;

	/* Number of active swapfiles */
	atomic_t nr_swapfiles;

#ifdef CONFIG_BTRFS_FS_RUN_SANITY_TESTS
#error "klp-ccp: non-taken branch"
#endif
	u64 defrag_trans_start;
	struct btrfs_key defrag_progress;
	struct btrfs_key defrag_max;
	char *name;

	/* the dirty list is only used by non-reference counted roots */
	struct list_head dirty_list;

	struct list_head root_list;

	spinlock_t log_extents_lock[2];
	struct list_head logged_list[2];

	int orphan_cleanup_state;

	spinlock_t inode_lock;
	/* red-black tree that keeps track of in-memory inodes */
	struct rb_root inode_tree;

	/*
	 * radix tree that keeps track of delayed nodes of every inode,
	 * protected by inode_lock
	 */
	struct radix_tree_root delayed_nodes_tree;

	struct super_block_dev sbdev;

	spinlock_t root_item_lock;
	refcount_t refs;

	struct mutex delalloc_mutex;
	spinlock_t delalloc_lock;
	/*
	 * all of the inodes that have delalloc bytes.  It is possible for
	 * this list to be empty even when there is still dirty data=ordered
	 * extents waiting to finish IO.
	 */
	struct list_head delalloc_inodes;
	struct list_head delalloc_root;
	u64 nr_delalloc_inodes;

	struct mutex ordered_extent_mutex;
	/*
	 * this is used by the balancing code to wait for all the pending
	 * ordered extents
	 */
	spinlock_t ordered_extent_lock;

	/*
	 * all of the data=ordered extents pending writeback
	 * these can span multiple transactions and basically include
	 * every dirty data page that isn't from nodatacow
	 */
	struct list_head ordered_extents;
	struct list_head ordered_root;
	u64 nr_ordered_extents;

	/*
	 * Not empty if this subvolume root has gone through tree block swap
	 * (relocation)
	 *
	 * Will be used by reloc_control::dirty_subvol_roots.
	 */
	struct list_head reloc_dirty_list;

	/*
	 * Number of currently running SEND ioctls to prevent
	 * manipulation with the read-only status via SUBVOL_SETFLAGS
	 */
	int send_in_progress;
	/*
	 * Number of currently running deduplication operations that have a
	 * destination inode belonging to this root. Protected by the lock
	 * root_item_lock.
	 */
	int dedupe_in_progress;
	struct btrfs_subvolume_writers *subv_writers;
	atomic_t will_be_snapshoted;

	/* For qgroup metadata reserved space */
	spinlock_t qgroup_meta_rsv_lock;
	u64 qgroup_meta_rsv_pertrans;
	u64 qgroup_meta_rsv_prealloc;
};

#define BTRFS_MOUNT_ENOSPC_DEBUG	 (1 << 15)

#define btrfs_test_opt(fs_info, opt)	((fs_info)->mount_opt & \
					 BTRFS_MOUNT_##opt)

enum btrfs_reserve_flush_enum {
	/* If we are in the transaction, we can't flush anything.*/
	BTRFS_RESERVE_NO_FLUSH,
	/*
	 * Flushing delalloc may cause deadlock somewhere, in this
	 * case, use FLUSH LIMIT
	 */
	BTRFS_RESERVE_FLUSH_LIMIT,
	BTRFS_RESERVE_FLUSH_EVICT,
	BTRFS_RESERVE_FLUSH_ALL,
	BTRFS_RESERVE_FLUSH_ALL_STEAL,
};

enum btrfs_flush_state {
	FLUSH_DELAYED_ITEMS_NR	=	1,
	FLUSH_DELAYED_ITEMS	=	2,
	FLUSH_DELAYED_REFS_NR	=	3,
	FLUSH_DELAYED_REFS	=	4,
	FLUSH_DELALLOC		=	5,
	FLUSH_DELALLOC_WAIT	=	6,
	ALLOC_CHUNK		=	7,
	ALLOC_CHUNK_FORCE	=	8,
	RUN_DELAYED_IPUTS	=	9,
	COMMIT_TRANS		=	10,
};

static __printf(2, 3)
void (*klpe_btrfs_printk)(const struct btrfs_fs_info *fs_info, const char *fmt, ...);

#define klpr_btrfs_info(fs_info, fmt, args...) \
	(*klpe_btrfs_printk)(fs_info, KERN_INFO fmt, ##args)

/* klp-ccp: from fs/btrfs/space-info.h */
struct btrfs_space_info {
	spinlock_t lock;

	u64 total_bytes;	/* total bytes in the space,
				   this doesn't take mirrors into account */
	u64 bytes_used;		/* total bytes used,
				   this doesn't take mirrors into account */
	u64 bytes_pinned;	/* total bytes pinned, will be freed when the
				   transaction finishes */
	u64 bytes_reserved;	/* total bytes the allocator has reserved for
				   current allocations */
	u64 bytes_may_use;	/* number of bytes that may be used for
				   delalloc/allocations */
	u64 bytes_readonly;	/* total bytes that are read only */

	u64 max_extent_size;	/* This will hold the maximum extent size of
				   the space info if we had an ENOSPC in the
				   allocator. */

	unsigned int full:1;	/* indicates that we cannot allocate any more
				   chunks for this space */
	unsigned int chunk_alloc:1;	/* set if we are allocating a chunk */

	unsigned int flush:1;		/* set if we are trying to make space */

	unsigned int force_alloc;	/* set if we need to force a chunk
					   alloc for this space */

	u64 disk_used;		/* total bytes used on disk */
	u64 disk_total;		/* total bytes on disk, takes mirrors into
				   account */

	u64 flags;

	/*
	 * bytes_pinned is kept in line with what is actually pinned, as in
	 * we've called update_block_group and dropped the bytes_used counter
	 * and increased the bytes_pinned counter.  However this means that
	 * bytes_pinned does not reflect the bytes that will be pinned once the
	 * delayed refs are flushed, so this counter is inc'ed every time we
	 * call btrfs_free_extent so it is a realtime count of what will be
	 * freed once the transaction is committed.  It will be zeroed every
	 * time the transaction commits.
	 */
	struct percpu_counter total_bytes_pinned;

	struct list_head list;
	/* Protected by the spinlock 'lock'. */
	struct list_head ro_bgs;
	struct list_head priority_tickets;
	struct list_head tickets;
	/*
	 * tickets_id just indicates the next ticket will be handled, so note
	 * it's not stored per ticket.
	 */
	u64 tickets_id;

	struct rw_semaphore groups_sem;
	/* for block groups in our same type */
	struct list_head block_groups[BTRFS_NR_RAID_TYPES];
	wait_queue_head_t wait;

	struct kobject kobj;
	struct kobject *block_group_kobjs[BTRFS_NR_RAID_TYPES];
};

struct reserve_ticket {
	u64 bytes;
	int error;
	bool steal;
	struct list_head list;
	wait_queue_head_t wait;
};

static struct btrfs_space_info *(*klpe_btrfs_find_space_info)(struct btrfs_fs_info *info,
					       u64 flags);
static u64 (*klpe_btrfs_space_info_used)(struct btrfs_space_info *s_info,
			  bool may_use_included);

static void (*klpe_btrfs_try_granting_tickets)(struct btrfs_fs_info *fs_info,
				struct btrfs_space_info *space_info);

/* klp-ccp: from fs/btrfs/volumes.h */
#include <linux/bio.h>
#include <linux/btrfs.h>

static int (*klpe_btrfs_bg_type_to_factor)(u64 flags);

/* klp-ccp: from fs/btrfs/transaction.h */
#include <linux/refcount.h>
/* klp-ccp: from fs/btrfs/btrfs_inode.h */
#include <linux/hash.h>
/* klp-ccp: from fs/btrfs/delayed-inode.h */
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/refcount.h>
/* klp-ccp: from fs/btrfs/delayed-ref.h */
#include <linux/refcount.h>
/* klp-ccp: from fs/btrfs/math.h */
#include <asm/div64.h>

static inline u64 div_factor(u64 num, int factor)
{
	if (factor == 10)
		return num;
	num *= factor;
	return div_u64(num, 10);
}

static inline u64 div_factor_fine(u64 num, int factor)
{
	if (factor == 100)
		return num;
	num *= factor;
	return div_u64(num, 100);
}

/* klp-ccp: from fs/btrfs/block-group.h */
static u64 (*klpe_btrfs_get_alloc_profile)(struct btrfs_fs_info *fs_info, u64 orig_flags);

static inline u64 klpr_btrfs_metadata_alloc_profile(struct btrfs_fs_info *fs_info)
{
	return (*klpe_btrfs_get_alloc_profile)(fs_info, BTRFS_BLOCK_GROUP_METADATA);
}

static inline u64 klpr_btrfs_system_alloc_profile(struct btrfs_fs_info *fs_info)
{
	return (*klpe_btrfs_get_alloc_profile)(fs_info, BTRFS_BLOCK_GROUP_SYSTEM);
}

/* klp-ccp: from fs/btrfs/space-info.c */
/*
 * Fix bsc#1178046
 *  -1 line, +1 line
 */
static int klpp_can_overcommit(struct btrfs_fs_info *fs_info,
			  struct btrfs_space_info *space_info, u64 bytes,
			  enum btrfs_reserve_flush_enum flush)
{
	/*
	 * Fix bsc#1178046
	 *  -1 line
	 */
	u64 profile;
	u64 avail;
	u64 used;
	int factor;

	/* Don't overcommit when in mixed mode. */
	if (space_info->flags & BTRFS_BLOCK_GROUP_DATA)
		return 0;

	if (space_info->flags & BTRFS_BLOCK_GROUP_METADATA)
		profile = klpr_btrfs_metadata_alloc_profile(fs_info);
	else
		profile = klpr_btrfs_system_alloc_profile(fs_info);

	used = (*klpe_btrfs_space_info_used)(space_info, true);

	spin_lock(&fs_info->free_chunk_lock);
	avail = fs_info->free_chunk_space;
	spin_unlock(&fs_info->free_chunk_lock);

	/*
	 * If we have dup, raid1 or raid10 then only half of the free
	 * space is actually useable.  For raid56, the space info used
	 * doesn't include the parity drive, so we don't have to
	 * change the math
	 */
	factor = (*klpe_btrfs_bg_type_to_factor)(profile);
	avail = div_u64(avail, factor);

	/*
	 * If we aren't flushing all things, let us overcommit up to
	 * 1/2th of the space. If we can flush, don't let us overcommit
	 * too much, let it overcommit up to 1/8 of the space.
	 */
	if (flush == BTRFS_RESERVE_FLUSH_ALL)
		avail >>= 3;
	else
		avail >>= 1;

	if (used + bytes < space_info->total_bytes + avail)
		return 1;
	return 0;
}

static void (*klpe___btrfs_dump_space_info)(struct btrfs_fs_info *fs_info,
				    struct btrfs_space_info *info);

static int (*klpe_flush_space)(struct btrfs_fs_info *fs_info,
		       struct btrfs_space_info *space_info, u64 num_bytes,
		       int state);

/*
 * Fix bsc#1178046
 *  -1 line, +1 line
 */
static inline u64
klpp_btrfs_calc_reclaim_metadata_size(struct btrfs_fs_info *fs_info,
				 struct btrfs_space_info *space_info)
{
	struct reserve_ticket *ticket;
	u64 used;
	u64 expected;
	u64 to_reclaim = 0;

	list_for_each_entry(ticket, &space_info->tickets, list)
		to_reclaim += ticket->bytes;
	list_for_each_entry(ticket, &space_info->priority_tickets, list)
		to_reclaim += ticket->bytes;
	if (to_reclaim)
		return to_reclaim;

	to_reclaim = min_t(u64, num_online_cpus() * SZ_1M, SZ_16M);
	/*
	 * Fix bsc#1178046
	 *  -1 line, +1 line
	 */
	if (klpp_can_overcommit(fs_info, space_info, to_reclaim,
			   BTRFS_RESERVE_FLUSH_ALL))
		return 0;

	used = space_info->bytes_used + space_info->bytes_reserved +
	       space_info->bytes_pinned + space_info->bytes_readonly +
	       space_info->bytes_may_use;
	/*
	 * Fix bsc#1178046
	 *  -1 line, +2 lines
	 */
	if (klpp_can_overcommit(fs_info, space_info, SZ_1M,
				 BTRFS_RESERVE_FLUSH_ALL))
		expected = div_factor_fine(space_info->total_bytes, 95);
	else
		expected = div_factor_fine(space_info->total_bytes, 90);

	if (used > expected)
		to_reclaim = used - expected;
	else
		to_reclaim = 0;
	to_reclaim = min(to_reclaim, space_info->bytes_may_use +
				     space_info->bytes_reserved);
	return to_reclaim;
}

static bool steal_from_global_rsv(struct btrfs_fs_info *fs_info,
				  struct btrfs_space_info *space_info,
				  struct reserve_ticket *ticket)
{
	struct btrfs_block_rsv *global_rsv = &fs_info->global_block_rsv;
	u64 min_bytes;

	if (global_rsv->space_info != space_info)
		return false;

	spin_lock(&global_rsv->lock);
	min_bytes = div_factor(global_rsv->size, 1);
	if (global_rsv->reserved < min_bytes + ticket->bytes) {
		spin_unlock(&global_rsv->lock);
		return false;
	}
	global_rsv->reserved -= ticket->bytes;
	ticket->bytes = 0;
	list_del_init(&ticket->list);
	wake_up(&ticket->wait);
	space_info->tickets_id++;
	if (global_rsv->reserved < global_rsv->size)
		global_rsv->full = 0;
	spin_unlock(&global_rsv->lock);

	return true;
}

static bool klpr_maybe_fail_all_tickets(struct btrfs_fs_info *fs_info,
				   struct btrfs_space_info *space_info)
{
	struct reserve_ticket *ticket;
	u64 tickets_id = space_info->tickets_id;
	u64 first_ticket_bytes = 0;

	if (btrfs_test_opt(fs_info, ENOSPC_DEBUG)) {
		klpr_btrfs_info(fs_info, "cannot satisfy tickets, dumping space info");
		(*klpe___btrfs_dump_space_info)(fs_info, space_info);
	}

	while (!list_empty(&space_info->tickets) &&
	       tickets_id == space_info->tickets_id) {
		ticket = list_first_entry(&space_info->tickets,
					  struct reserve_ticket, list);

		if (ticket->steal &&
		    steal_from_global_rsv(fs_info, space_info, ticket))
			return true;
		/*
		 * may_commit_transaction will avoid committing the transaction
		 * if it doesn't feel like the space reclaimed by the commit
		 * would result in the ticket succeeding.  However if we have a
		 * smaller ticket in the queue it may be small enough to be
		 * satisified by committing the transaction, so if any
		 * subsequent ticket is smaller than the first ticket go ahead
		 * and send us back for another loop through the enospc flushing
		 * code.
		 */
		if (first_ticket_bytes == 0)
			first_ticket_bytes = ticket->bytes;
		else if (first_ticket_bytes > ticket->bytes)
			return true;

		if (btrfs_test_opt(fs_info, ENOSPC_DEBUG))
			klpr_btrfs_info(fs_info, "failing ticket with %llu bytes",
				   ticket->bytes);

		list_del_init(&ticket->list);
		ticket->error = -ENOSPC;
		wake_up(&ticket->wait);

		/*
		 * We're just throwing tickets away, so more flushing may not
		 * trip over btrfs_try_granting_tickets, so we need to call it
		 * here to see if we can make progress with the next ticket in
		 * the list.
		 */
		(*klpe_btrfs_try_granting_tickets)(fs_info, space_info);
	}
	return (tickets_id != space_info->tickets_id);
}

void klpp_btrfs_async_reclaim_metadata_space(struct work_struct *work)
{
	struct btrfs_fs_info *fs_info;
	struct btrfs_space_info *space_info;
	u64 to_reclaim;
	int flush_state;
	int commit_cycles = 0;
	u64 last_tickets_id;

	fs_info = container_of(work, struct btrfs_fs_info, async_reclaim_work);
	space_info = (*klpe_btrfs_find_space_info)(fs_info, BTRFS_BLOCK_GROUP_METADATA);

	spin_lock(&space_info->lock);
	/*
	 * Fix bsc#1178046
	 *  -2 lines, +1 line
	 */
	to_reclaim = klpp_btrfs_calc_reclaim_metadata_size(fs_info, space_info);
	if (!to_reclaim) {
		space_info->flush = 0;
		spin_unlock(&space_info->lock);
		return;
	}
	last_tickets_id = space_info->tickets_id;
	spin_unlock(&space_info->lock);

	flush_state = FLUSH_DELAYED_ITEMS_NR;
	do {
		struct reserve_ticket *ticket;
		int ret;

		ret = (*klpe_flush_space)(fs_info, space_info, to_reclaim, flush_state);
		spin_lock(&space_info->lock);
		if (list_empty(&space_info->tickets)) {
			space_info->flush = 0;
			spin_unlock(&space_info->lock);
			return;
		}
		/*
		 * Fix bsc#1178046
		 *  -1 line, +1 line
		 */
		to_reclaim = klpp_btrfs_calc_reclaim_metadata_size(fs_info,
							      space_info);
		ticket = list_first_entry(&space_info->tickets,
					  struct reserve_ticket, list);
		if (last_tickets_id == space_info->tickets_id) {
			flush_state++;
		} else {
			last_tickets_id = space_info->tickets_id;
			flush_state = FLUSH_DELAYED_ITEMS_NR;
			if (commit_cycles)
				commit_cycles--;
		}

		/*
		 * We don't want to force a chunk allocation until we've tried
		 * pretty hard to reclaim space.  Think of the case where we
		 * freed up a bunch of space and so have a lot of pinned space
		 * to reclaim.  We would rather use that than possibly create a
		 * underutilized metadata chunk.  So if this is our first run
		 * through the flushing state machine skip ALLOC_CHUNK_FORCE and
		 * commit the transaction.  If nothing has changed the next go
		 * around then we can force a chunk allocation.
		 */
		if (flush_state == ALLOC_CHUNK_FORCE && !commit_cycles)
			flush_state++;

		if (flush_state > COMMIT_TRANS) {
			commit_cycles++;
			if (commit_cycles > 2) {
				if (klpr_maybe_fail_all_tickets(fs_info, space_info)) {
					flush_state = FLUSH_DELAYED_ITEMS_NR;
					commit_cycles--;
				} else {
					space_info->flush = 0;
				}
			} else {
				flush_state = FLUSH_DELAYED_ITEMS_NR;
			}
		}
		spin_unlock(&space_info->lock);
	} while (flush_state <= COMMIT_TRANS);
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "btrfs_printk", (void *)&klpe_btrfs_printk, "btrfs" },
	{ "btrfs_find_space_info", (void *)&klpe_btrfs_find_space_info,
	  "btrfs" },
	{ "btrfs_space_info_used", (void *)&klpe_btrfs_space_info_used,
	  "btrfs" },
	{ "btrfs_try_granting_tickets",
	  (void *)&klpe_btrfs_try_granting_tickets, "btrfs" },
	{ "btrfs_bg_type_to_factor", (void *)&klpe_btrfs_bg_type_to_factor,
	  "btrfs" },
	{ "btrfs_get_alloc_profile", (void *)&klpe_btrfs_get_alloc_profile,
	  "btrfs" },
	{ "__btrfs_dump_space_info", (void *)&klpe___btrfs_dump_space_info,
	  "btrfs" },
	{ "flush_space", (void *)&klpe_flush_space, "btrfs" },
};

static int livepatch_bsc1178046_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1178046_module_nb = {
	.notifier_call = livepatch_bsc1178046_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1178046_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1178046_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1178046_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1178046_module_nb);
}
