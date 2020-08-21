/*
 * livepatch_bsc1173869
 *
 * Fix for CVE-2019-19447, bsc#1173869
 *
 *  Upstream commit:
 *  c7df4a1ecb85 ("ext4: work around deleting a file with i_nlink == 0 safely")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  c52fef6460e160e37f2c44895dd07cb2296cded3
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  d10c0d338bb6e91df601fb58e345921513f9bd49
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

#if !IS_MODULE(CONFIG_EXT4_FS)
#error "Live patch supports only CONFIG_EXT4_FS=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/tracepoint.h>
#include "livepatch_bsc1173869.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "ext4"

/* from include/linux/tracepoint.h */
#define KLPR___DECLARE_TRACE(name, proto, args, cond, data_proto, data_args) \
	static struct tracepoint (*klpe___tracepoint_##name);		\
	static inline void klpr_trace_##name(proto)			\
	{								\
		if (unlikely(static_key_enabled(&(*klpe___tracepoint_##name).key))) \
			__DO_TRACE(&(*klpe___tracepoint_##name),	\
				TP_PROTO(data_proto),			\
				TP_ARGS(data_args),			\
				TP_CONDITION(cond), 0);		\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {		\
			rcu_read_lock_sched_notrace();			\
			rcu_dereference_sched((*klpe___tracepoint_##name).funcs); \
			rcu_read_unlock_sched_notrace();		\
		}							\
	}								\

#define KLPR_DECLARE_TRACE(name, proto, args)				\
	KLPR___DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
			cpu_online(raw_smp_processor_id()),		\
			PARAMS(void *__data, proto),			\
			PARAMS(__data, args))

#define KLPR_TRACE_EVENT(name, proto, args)	\
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))


/* klp-ccp: from fs/ext4/namei.c */
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/time.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/bio.h>
/* klp-ccp: from fs/ext4/ext4.h */
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/magic.h>
#include <linux/jbd2.h>
#include <linux/quota.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/seqlock.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/percpu_counter.h>
#include <linux/ratelimit.h>
#include <crypto/hash.h>
#include <linux/percpu-rwsem.h>

typedef unsigned long long ext4_fsblk_t;

typedef __u32 ext4_lblk_t;

typedef unsigned int ext4_group_t;

enum {
	EXT4_INODE_SECRM	= 0,	/* Secure deletion */
	EXT4_INODE_UNRM		= 1,	/* Undelete */
	EXT4_INODE_COMPR	= 2,	/* Compress file */
	EXT4_INODE_SYNC		= 3,	/* Synchronous updates */
	EXT4_INODE_IMMUTABLE	= 4,	/* Immutable file */
	EXT4_INODE_APPEND	= 5,	/* writes to file may only append */
	EXT4_INODE_NODUMP	= 6,	/* do not dump file */
	EXT4_INODE_NOATIME	= 7,	/* do not update atime */
/* Reserved for compression usage... */
	EXT4_INODE_DIRTY	= 8,
	EXT4_INODE_COMPRBLK	= 9,	/* One or more compressed clusters */
	EXT4_INODE_NOCOMPR	= 10,	/* Don't compress */
	EXT4_INODE_ENCRYPT	= 11,	/* Encrypted file */
/* End compression flags --- maybe not all used */
	EXT4_INODE_INDEX	= 12,	/* hash-indexed directory */
	EXT4_INODE_IMAGIC	= 13,	/* AFS directory */
	EXT4_INODE_JOURNAL_DATA	= 14,	/* file data should be journaled */
	EXT4_INODE_NOTAIL	= 15,	/* file tail should not be merged */
	EXT4_INODE_DIRSYNC	= 16,	/* dirsync behaviour (directories only) */
	EXT4_INODE_TOPDIR	= 17,	/* Top of directory hierarchies*/
	EXT4_INODE_HUGE_FILE	= 18,	/* Set to each huge file */
	EXT4_INODE_EXTENTS	= 19,	/* Inode uses extents */
	EXT4_INODE_EA_INODE	= 21,	/* Inode used for large EA */
	EXT4_INODE_EOFBLOCKS	= 22,	/* Blocks allocated beyond EOF */
	EXT4_INODE_INLINE_DATA	= 28,	/* Data in inode. */
	EXT4_INODE_PROJINHERIT	= 29,	/* Create with parents projid */
	EXT4_INODE_RESERVED	= 31,	/* reserved for ext4 lib */
};

/* klp-ccp: from fs/ext4/extents_status.h */
struct ext4_es_tree {
	struct rb_root root;
	struct extent_status *cache_es;	/* recently accessed extent */
};

struct ext4_es_stats {
	unsigned long es_stats_shrunk;
	unsigned long es_stats_cache_hits;
	unsigned long es_stats_cache_misses;
	u64 es_stats_scan_time;
	u64 es_stats_max_scan_time;
	struct percpu_counter es_stats_all_cnt;
	struct percpu_counter es_stats_shk_cnt;
};

/* klp-ccp: from fs/ext4/ext4.h */
struct ext4_inode_info {
	__le32	i_data[15];	/* unconverted */
	__u32	i_dtime;
	ext4_fsblk_t	i_file_acl;

	/*
	 * i_block_group is the number of the block group which contains
	 * this file's inode.  Constant across the lifetime of the inode,
	 * it is ued for making block allocation decisions - we try to
	 * place a file's data blocks near its inode block, and new inodes
	 * near to their parent directory's inode.
	 */
	ext4_group_t	i_block_group;
	ext4_lblk_t	i_dir_start_lookup;
#if (BITS_PER_LONG < 64)
#error "klp-ccp: non-taken branch"
#endif
	unsigned long	i_flags;

	/*
	 * Extended attributes can be read independently of the main file
	 * data. Taking i_mutex even when reading would cause contention
	 * between readers of EAs and writers of regular file data, so
	 * instead we synchronize on xattr_sem when reading or changing
	 * EAs.
	 */
	struct rw_semaphore xattr_sem;

	struct list_head i_orphan;	/* unlinked but open inodes */

	/*
	 * i_disksize keeps track of what the inode size is ON DISK, not
	 * in memory.  During truncate, i_size is set to the new size by
	 * the VFS prior to calling ext4_truncate(), but the filesystem won't
	 * set i_disksize to 0 until the truncate is actually under way.
	 *
	 * The intent is that i_disksize always represents the blocks which
	 * are used by this file.  This allows recovery to restart truncate
	 * on orphans if we crash during truncate.  We actually write i_disksize
	 * into the on-disk inode when writing inodes out, instead of i_size.
	 *
	 * The only time when i_disksize and i_size may be different is when
	 * a truncate is in progress.  The only things which change i_disksize
	 * are ext4_get_block (growth) and ext4_truncate (shrinkth).
	 */
	loff_t	i_disksize;

	/*
	 * i_data_sem is for serialising ext4_truncate() against
	 * ext4_getblock().  In the 2.4 ext2 design, great chunks of inode's
	 * data tree are chopped off during truncate. We can't do that in
	 * ext4 because whenever we perform intermediate commits during
	 * truncate, the inode and all the metadata blocks *must* be in a
	 * consistent state which allows truncation of the orphans to restart
	 * during recovery.  Hence we must fix the get_block-vs-truncate race
	 * by other means, so we have i_data_sem.
	 */
	struct rw_semaphore i_data_sem;
	/*
	 * i_mmap_sem is for serializing page faults with truncate / punch hole
	 * operations. We have to make sure that new page cannot be faulted in
	 * a section of the inode that is being punched. We cannot easily use
	 * i_data_sem for this since we need protection for the whole punch
	 * operation and i_data_sem ranks below transaction start so we have
	 * to occasionally drop it.
	 */
	struct rw_semaphore i_mmap_sem;
	struct inode vfs_inode;
	struct jbd2_inode *jinode;

	spinlock_t i_raw_lock;	/* protects updates to the raw inode */

	/*
	 * File creation time. Its function is same as that of
	 * struct timespec i_{a,c,m}time in the generic inode.
	 */
	struct timespec i_crtime;

	/* mballoc */
	struct list_head i_prealloc_list;
	spinlock_t i_prealloc_lock;

	/* extents status tree */
	struct ext4_es_tree i_es_tree;
	rwlock_t i_es_lock;
	struct list_head i_es_list;
	unsigned int i_es_all_nr;	/* protected by i_es_lock */
	unsigned int i_es_shk_nr;	/* protected by i_es_lock */
	ext4_lblk_t i_es_shrink_lblk;	/* Offset where we start searching for
					   extents to shrink. Protected by
					   i_es_lock  */

	/* ialloc */
	ext4_group_t	i_last_alloc_group;

	/* allocation reservation info for delalloc */
	/* In case of bigalloc, these refer to clusters rather than blocks */
	unsigned int i_reserved_data_blocks;
	unsigned int i_reserved_meta_blocks;
	unsigned int i_allocated_meta_blocks;
	ext4_lblk_t i_da_metadata_calc_last_lblock;
	int i_da_metadata_calc_len;

	/* on-disk additional length */
	__u16 i_extra_isize;

	/* Indicate the inline data space. */
	u16 i_inline_off;
	u16 i_inline_size;

#ifdef CONFIG_QUOTA
	qsize_t i_reserved_quota;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	spinlock_t i_completed_io_lock;
	/*
	 * Completed IOs that need unwritten extents handling and have
	 * transaction reserved
	 */
	struct list_head i_rsv_conversion_list;
	struct work_struct i_rsv_conversion_work;
	atomic_t i_unwritten; /* Nr. of inflight conversions pending */

	spinlock_t i_block_reservation_lock;

	/*
	 * Transactions that contain inode's metadata needed to complete
	 * fsync and fdatasync, respectively.
	 */
	tid_t i_sync_tid;
	tid_t i_datasync_tid;

#ifdef CONFIG_QUOTA
	struct dquot *i_dquot[MAXQUOTAS];
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	__u32 i_csum_seed;

	kprojid_t i_projid;
};

#define EXT4_MOUNT_QUOTA		0x40000 /* Some quota option set */

#define test_opt(sb, opt)		(EXT4_SB(sb)->s_mount_opt & \
					 EXT4_MOUNT_##opt)

struct ext4_super_block {
/*00*/	__le32	s_inodes_count;		/* Inodes count */
	__le32	s_blocks_count_lo;	/* Blocks count */
	__le32	s_r_blocks_count_lo;	/* Reserved blocks count */
	__le32	s_free_blocks_count_lo;	/* Free blocks count */
/*10*/	__le32	s_free_inodes_count;	/* Free inodes count */
	__le32	s_first_data_block;	/* First Data Block */
	__le32	s_log_block_size;	/* Block size */
	__le32	s_log_cluster_size;	/* Allocation cluster size */
/*20*/	__le32	s_blocks_per_group;	/* # Blocks per group */
	__le32	s_clusters_per_group;	/* # Clusters per group */
	__le32	s_inodes_per_group;	/* # Inodes per group */
	__le32	s_mtime;		/* Mount time */
/*30*/	__le32	s_wtime;		/* Write time */
	__le16	s_mnt_count;		/* Mount count */
	__le16	s_max_mnt_count;	/* Maximal mount count */
	__le16	s_magic;		/* Magic signature */
	__le16	s_state;		/* File system state */
	__le16	s_errors;		/* Behaviour when detecting errors */
	__le16	s_minor_rev_level;	/* minor revision level */
/*40*/	__le32	s_lastcheck;		/* time of last check */
	__le32	s_checkinterval;	/* max. time between checks */
	__le32	s_creator_os;		/* OS */
	__le32	s_rev_level;		/* Revision level */
/*50*/	__le16	s_def_resuid;		/* Default uid for reserved blocks */
	__le16	s_def_resgid;		/* Default gid for reserved blocks */
	/*
	 * These fields are for EXT4_DYNAMIC_REV superblocks only.
	 *
	 * Note: the difference between the compatible feature set and
	 * the incompatible feature set is that if there is a bit set
	 * in the incompatible feature set that the kernel doesn't
	 * know about, it should refuse to mount the filesystem.
	 *
	 * e2fsck's requirements are more strict; if it doesn't know
	 * about a feature in either the compatible or incompatible
	 * feature set, it must abort and not try to meddle with
	 * things it doesn't understand...
	 */
	__le32	s_first_ino;		/* First non-reserved inode */
	__le16  s_inode_size;		/* size of inode structure */
	__le16	s_block_group_nr;	/* block group # of this superblock */
	__le32	s_feature_compat;	/* compatible feature set */
/*60*/	__le32	s_feature_incompat;	/* incompatible feature set */
	__le32	s_feature_ro_compat;	/* readonly-compatible feature set */
/*68*/	__u8	s_uuid[16];		/* 128-bit uuid for volume */
/*78*/	char	s_volume_name[16];	/* volume name */
/*88*/	char	s_last_mounted[64];	/* directory where last mounted */
/*C8*/	__le32	s_algorithm_usage_bitmap; /* For compression */
	/*
	 * Performance hints.  Directory preallocation should only
	 * happen if the EXT4_FEATURE_COMPAT_DIR_PREALLOC flag is on.
	 */
	__u8	s_prealloc_blocks;	/* Nr of blocks to try to preallocate*/
	__u8	s_prealloc_dir_blocks;	/* Nr to preallocate for dirs */
	__le16	s_reserved_gdt_blocks;	/* Per group desc for online growth */
	/*
	 * Journaling support valid if EXT4_FEATURE_COMPAT_HAS_JOURNAL set.
	 */
/*D0*/	__u8	s_journal_uuid[16];	/* uuid of journal superblock */
/*E0*/	__le32	s_journal_inum;		/* inode number of journal file */
	__le32	s_journal_dev;		/* device number of journal file */
	__le32	s_last_orphan;		/* start of list of inodes to delete */
	__le32	s_hash_seed[4];		/* HTREE hash seed */
	__u8	s_def_hash_version;	/* Default hash version to use */
	__u8	s_jnl_backup_type;
	__le16  s_desc_size;		/* size of group descriptor */
/*100*/	__le32	s_default_mount_opts;
	__le32	s_first_meta_bg;	/* First metablock block group */
	__le32	s_mkfs_time;		/* When the filesystem was created */
	__le32	s_jnl_blocks[17];	/* Backup of the journal inode */
	/* 64bit support valid if EXT4_FEATURE_COMPAT_64BIT */
/*150*/	__le32	s_blocks_count_hi;	/* Blocks count */
	__le32	s_r_blocks_count_hi;	/* Reserved blocks count */
	__le32	s_free_blocks_count_hi;	/* Free blocks count */
	__le16	s_min_extra_isize;	/* All inodes have at least # bytes */
	__le16	s_want_extra_isize; 	/* New inodes should reserve # bytes */
	__le32	s_flags;		/* Miscellaneous flags */
	__le16  s_raid_stride;		/* RAID stride */
	__le16  s_mmp_update_interval;  /* # seconds to wait in MMP checking */
	__le64  s_mmp_block;            /* Block for multi-mount protection */
	__le32  s_raid_stripe_width;    /* blocks on all data disks (N*stride)*/
	__u8	s_log_groups_per_flex;  /* FLEX_BG group size */
	__u8	s_checksum_type;	/* metadata checksum algorithm used */
	__u8	s_encryption_level;	/* versioning level for encryption */
	__u8	s_reserved_pad;		/* Padding to next 32bits */
	__le64	s_kbytes_written;	/* nr of lifetime kilobytes written */
	__le32	s_snapshot_inum;	/* Inode number of active snapshot */
	__le32	s_snapshot_id;		/* sequential ID of active snapshot */
	__le64	s_snapshot_r_blocks_count; /* reserved blocks for active
					      snapshot's future use */
	__le32	s_snapshot_list;	/* inode number of the head of the
					   on-disk snapshot list */
	__le32	s_error_count;		/* number of fs errors */
	__le32	s_first_error_time;	/* first time an error happened */
	__le32	s_first_error_ino;	/* inode involved in first error */
	__le64	s_first_error_block;	/* block involved of first error */
	__u8	s_first_error_func[32];	/* function where the error happened */
	__le32	s_first_error_line;	/* line number where error happened */
	__le32	s_last_error_time;	/* most recent time of an error */
	__le32	s_last_error_ino;	/* inode involved in last error */
	__le32	s_last_error_line;	/* line number where error happened */
	__le64	s_last_error_block;	/* block involved of last error */
	__u8	s_last_error_func[32];	/* function where the error happened */
	__u8	s_mount_opts[64];
	__le32	s_usr_quota_inum;	/* inode for tracking user quota */
	__le32	s_grp_quota_inum;	/* inode for tracking group quota */
	__le32	s_overhead_clusters;	/* overhead blocks/clusters in fs */
	__le32	s_backup_bgs[2];	/* groups with sparse_super2 SBs */
	__u8	s_encrypt_algos[4];	/* Encryption algorithms in use  */
	__u8	s_encrypt_pw_salt[16];	/* Salt used for string2key algorithm */
	__le32	s_lpf_ino;		/* Location of the lost+found inode */
	__le32	s_prj_quota_inum;	/* inode for tracking project quota */
	__le32	s_checksum_seed;	/* crc32c(uuid) if csum_seed set */
	__le32	s_reserved[98];		/* Padding to the end of the block */
	__le32	s_checksum;		/* crc32c(superblock) */
};

#ifdef __KERNEL__

#define EXT4_MAXQUOTAS 3

struct ext4_sb_info {
	unsigned long s_desc_size;	/* Size of a group descriptor in bytes */
	unsigned long s_inodes_per_block;/* Number of inodes per block */
	unsigned long s_blocks_per_group;/* Number of blocks in a group */
	unsigned long s_clusters_per_group; /* Number of clusters in a group */
	unsigned long s_inodes_per_group;/* Number of inodes in a group */
	unsigned long s_itb_per_group;	/* Number of inode table blocks per group */
	unsigned long s_gdb_count;	/* Number of group descriptor blocks */
	unsigned long s_desc_per_block;	/* Number of group descriptors per block */
	ext4_group_t s_groups_count;	/* Number of groups in the fs */
	ext4_group_t s_blockfile_groups;/* Groups acceptable for non-extent files */
	unsigned long s_overhead;  /* # of fs overhead clusters */
	unsigned int s_cluster_ratio;	/* Number of blocks per cluster */
	unsigned int s_cluster_bits;	/* log2 of s_cluster_ratio */
	loff_t s_bitmap_maxbytes;	/* max bytes for bitmap files */
	struct buffer_head * s_sbh;	/* Buffer containing the super block */
	struct ext4_super_block *s_es;	/* Pointer to the super block in the buffer */
	struct buffer_head **s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_opt2;
	unsigned int s_mount_flags;
	unsigned int s_def_mount_opt;
	ext4_fsblk_t s_sb_block;
	atomic64_t s_resv_clusters;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned short s_mount_state;
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	spinlock_t s_next_gen_lock;
	u32 s_next_generation;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;	/* 3 if hash should be signed, 0 if not */
	struct percpu_counter s_freeclusters_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyclusters_counter;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;
	struct super_block *s_sb;

	/* Journaling */
	struct journal_s *s_journal;
	struct list_head s_orphan;
	struct mutex s_orphan_lock;
	unsigned long s_ext4_flags;		/* Ext4 superblock flags */
	unsigned long s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct block_device *journal_bdev;
#ifdef CONFIG_QUOTA
	char __rcu *s_qf_names[EXT4_MAXQUOTAS];
	int s_jquota_fmt;			/* Format of quota to use */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	unsigned int s_want_extra_isize; /* New inodes should reserve # bytes */
	struct rb_root system_blks;

#ifdef EXTENTS_STATS
#error "klp-ccp: non-taken branch"
#endif
	struct ext4_group_info ***s_group_info;
	struct inode *s_buddy_cache;
	spinlock_t s_md_lock;
	unsigned short *s_mb_offsets;
	unsigned int *s_mb_maxs;
	unsigned int s_group_info_size;
	unsigned int s_mb_free_pending;

	/* tunables */
	unsigned long s_stripe;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_max_dir_size_kb;
	/* where last allocation was done - for stream allocation */
	unsigned long s_mb_last_group;
	unsigned long s_mb_last_start;

	/* stats for buddy allocator */
	atomic_t s_bal_reqs;	/* number of reqs with len > 1 */
	atomic_t s_bal_success;	/* we found long enough chunks */
	atomic_t s_bal_allocated;	/* in blocks */
	atomic_t s_bal_ex_scanned;	/* total extents scanned */
	atomic_t s_bal_goals;	/* goal hits */
	atomic_t s_bal_breaks;	/* too long searches */
	atomic_t s_bal_2orders;	/* 2^order hits */
	spinlock_t s_bal_lock;
	unsigned long s_mb_buddies_generated;
	unsigned long long s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;

	/* locality groups */
	struct ext4_locality_group __percpu *s_locality_groups;

	/* for write statistics */
	unsigned long s_sectors_written_start;
	u64 s_kbytes_written;

	/* the size of zero-out chunk */
	unsigned int s_extent_max_zeroout_kb;

	unsigned int s_log_groups_per_flex;
	struct flex_groups *s_flex_groups;
	ext4_group_t s_flex_groups_allocated;

	/* workqueue for reserved extent conversions (buffered io) */
	struct workqueue_struct *rsv_conversion_wq;

	/* timer for periodic error stats printing */
	struct timer_list s_err_report;

	/* Lazy inode table initialization info */
	struct ext4_li_request *s_li_request;
	/* Wait multiplier for lazy initialization thread */
	unsigned int s_li_wait_mult;

	/* Kernel thread for multiple mount protection */
	struct task_struct *s_mmp_tsk;

	/* record the last minlen when FITRIM is called. */
	atomic_t s_last_trim_minblks;

	/* Reference to checksum algorithm driver via cryptoapi */
	struct crypto_shash *s_chksum_driver;

	/* Precomputed FS UUID checksum for seeding other checksums */
	__u32 s_csum_seed;

	/* Reclaim extents from extent status tree */
	struct shrinker s_es_shrinker;
	struct list_head s_es_list;	/* List of inodes with reclaimable extents */
	long s_es_nr_inode;
	struct ext4_es_stats s_es_stats;
	struct mb_cache *s_mb_cache;
	spinlock_t s_es_lock ____cacheline_aligned_in_smp;

	/* Ratelimit ext4 messages. */
	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;

	/* Barrier between changing inodes' journal flags and writepages ops. */
	struct percpu_rw_semaphore s_journal_flag_rwsem;
	struct dax_device *s_daxdev;
};

static inline struct ext4_sb_info *EXT4_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}
static inline struct ext4_inode_info *EXT4_I(struct inode *inode)
{
	return container_of(inode, struct ext4_inode_info, vfs_inode);
}

static inline void ext4_clear_inode_flag(struct inode *inode, int bit);

static inline void ext4_clear_inode_flag(struct inode *inode, int bit)
{
	clear_bit(bit + (0), &EXT4_I(inode)->i_flags);
}

#else
#error "klp-ccp: non-taken branch"
#endif

#define EXT4_FEATURE_COMPAT_DIR_INDEX		0x0020

#define EXT4_FEATURE_RO_COMPAT_QUOTA		0x0100

#define EXT4_FEATURE_INCOMPAT_EXTENTS		0x0040 /* extents support */

static inline bool ext4_has_feature_dir_index(struct super_block *sb)
{
	return ((EXT4_SB(sb)->s_es->s_feature_compat &
		cpu_to_le32(EXT4_FEATURE_COMPAT_DIR_INDEX)) != 0);
}

static inline bool ext4_has_feature_quota(struct super_block *sb)
{
	return ((EXT4_SB(sb)->s_es->s_feature_ro_compat &
		cpu_to_le32(EXT4_FEATURE_RO_COMPAT_QUOTA)) != 0);
}

static inline bool ext4_has_feature_extents(struct super_block *sb)
{
	return ((EXT4_SB(sb)->s_es->s_feature_incompat &
		cpu_to_le32(EXT4_FEATURE_INCOMPAT_EXTENTS)) != 0);
}

#define EXT4_FLAGS_SHUTDOWN	1

static inline int ext4_forced_shutdown(struct ext4_sb_info *sbi)
{
	return test_bit(EXT4_FLAGS_SHUTDOWN, &sbi->s_ext4_flags);
}

#define EXT4_NAME_LEN 255

struct ext4_dir_entry_2 {
	__le32	inode;			/* Inode number */
	__le16	rec_len;		/* Directory entry length */
	__u8	name_len;		/* Name length */
	__u8	file_type;
	char	name[EXT4_NAME_LEN];	/* File name */
};

#ifdef __KERNEL__

static inline void ext4_update_dx_flag(struct inode *inode)
{
	if (!ext4_has_feature_dir_index(inode->i_sb))
		ext4_clear_inode_flag(inode, EXT4_INODE_INDEX);
}

static int (*klpe_ext4_orphan_add)(handle_t *, struct inode *);

static __printf(4, 5)
void (*klpe___ext4_warning_inode)(const struct inode *inode, const char *function,
			  unsigned int line, const char *fmt, ...);

#define klpr_ext4_warning_inode(inode, fmt, ...)				\
	(*klpe___ext4_warning_inode)(inode, __func__, __LINE__, fmt, ##__VA_ARGS__)

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif	/* __KERNEL__ */

/* klp-ccp: from fs/ext4/ext4_jbd2.h */
#include <linux/fs.h>
#include <linux/jbd2.h>

#define EXT4_SINGLEDATA_TRANS_BLOCKS(sb)				\
	(ext4_has_feature_extents(sb) ? 20U : 8U)

#define EXT4_XATTR_TRANS_BLOCKS		6U

#define EXT4_DATA_TRANS_BLOCKS(sb)	(EXT4_SINGLEDATA_TRANS_BLOCKS(sb) + \
					 EXT4_XATTR_TRANS_BLOCKS - 2 + \
					 EXT4_MAXQUOTAS_TRANS_BLOCKS(sb))

#ifdef CONFIG_QUOTA

#define EXT4_QUOTA_TRANS_BLOCKS(sb) ((test_opt(sb, QUOTA) ||\
		ext4_has_feature_quota(sb)) ? 1 : 0)

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#define EXT4_MAXQUOTAS_TRANS_BLOCKS(sb) (EXT4_MAXQUOTAS*EXT4_QUOTA_TRANS_BLOCKS(sb))

#define EXT4_HT_DIR              4

static int (*klpe_ext4_mark_inode_dirty)(handle_t *handle, struct inode *inode);

static handle_t *(*klpe___ext4_journal_start_sb)(struct super_block *sb, unsigned int line,
				  int type, int blocks, int rsv_blocks);
static int (*klpe___ext4_journal_stop)(const char *where, unsigned int line, handle_t *handle);

#define EXT4_NOJOURNAL_MAX_REF_COUNT ((unsigned long) 4096)

static inline int ext4_handle_valid(handle_t *handle)
{
	if ((unsigned long)handle < EXT4_NOJOURNAL_MAX_REF_COUNT)
		return 0;
	return 1;
}

static inline void ext4_handle_sync(handle_t *handle)
{
	if (ext4_handle_valid(handle))
		handle->h_sync = 1;
}

#define klpr_ext4_journal_start(inode, type, nblocks)			\
	(klpr___ext4_journal_start)((inode), __LINE__, (type), (nblocks), 0)

static inline handle_t *klpr___ext4_journal_start(struct inode *inode,
					     unsigned int line, int type,
					     int blocks, int rsv_blocks)
{
	return (*klpe___ext4_journal_start_sb)(inode->i_sb, line, type, blocks,
				       rsv_blocks);
}

#define klpr_ext4_journal_stop(handle) \
	(*klpe___ext4_journal_stop)(__func__, __LINE__, (handle))

/* klp-ccp: from include/trace/events/ext4.h */
KLPR_TRACE_EVENT(ext4_unlink_enter,
	TP_PROTO(struct inode *parent, struct dentry *dentry),

	TP_ARGS(parent, dentry)
);

KLPR_TRACE_EVENT(ext4_unlink_exit,
	TP_PROTO(struct dentry *dentry, int ret),

	TP_ARGS(dentry, ret)
);

/* klp-ccp: from fs/ext4/namei.c */
static struct buffer_head * (*klpe_ext4_find_entry) (struct inode *dir,
					const struct qstr *d_name,
					struct ext4_dir_entry_2 **res_dir,
					int *inlined);

static int (*klpe_ext4_delete_entry)(handle_t *handle,
			     struct inode *dir,
			     struct ext4_dir_entry_2 *de_del,
			     struct buffer_head *bh);

int klpp_ext4_unlink(struct inode *dir, struct dentry *dentry)
{
	int retval;
	struct inode *inode;
	struct buffer_head *bh;
	struct ext4_dir_entry_2 *de;
	handle_t *handle = NULL;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(dir->i_sb))))
		return -EIO;

	klpr_trace_ext4_unlink_enter(dir, dentry);
	/* Initialize quotas before so that eventual writes go
	 * in separate transaction */
	retval = dquot_initialize(dir);
	if (retval)
		return retval;
	retval = dquot_initialize(d_inode(dentry));
	if (retval)
		return retval;

	retval = -ENOENT;
	bh = (*klpe_ext4_find_entry)(dir, &dentry->d_name, &de, NULL);
	if (IS_ERR(bh))
		return PTR_ERR(bh);
	if (!bh)
		goto end_unlink;

	inode = d_inode(dentry);

	retval = -EFSCORRUPTED;
	if (le32_to_cpu(de->inode) != inode->i_ino)
		goto end_unlink;

	handle = klpr_ext4_journal_start(dir, EXT4_HT_DIR,
				    EXT4_DATA_TRANS_BLOCKS(dir->i_sb));
	if (IS_ERR(handle)) {
		retval = PTR_ERR(handle);
		handle = NULL;
		goto end_unlink;
	}

	if (IS_DIRSYNC(dir))
		ext4_handle_sync(handle);

	/*
	 * Fix CVE-2019-19447
	 *  -5 lines
	 */
	retval = (*klpe_ext4_delete_entry)(handle, dir, de, bh);
	if (retval)
		goto end_unlink;
	dir->i_ctime = dir->i_mtime = current_time(dir);
	ext4_update_dx_flag(dir);
	(*klpe_ext4_mark_inode_dirty)(handle, dir);
	/*
	 * Fix CVE-2019-19447
	 *  -1 line, +5 lines
	 */
	if (inode->i_nlink == 0)
		klpr_ext4_warning_inode(inode, "Deleting file '%.*s' with no links",
				   dentry->d_name.len, dentry->d_name.name);
	else
		drop_nlink(inode);
	if (!inode->i_nlink)
		(*klpe_ext4_orphan_add)(handle, inode);
	inode->i_ctime = current_time(inode);
	(*klpe_ext4_mark_inode_dirty)(handle, inode);

end_unlink:
	brelse(bh);
	if (handle)
		klpr_ext4_journal_stop(handle);
	klpr_trace_ext4_unlink_exit(dentry, retval);
	return retval;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__tracepoint_ext4_unlink_enter",
	  (void *)&klpe___tracepoint_ext4_unlink_enter, "ext4" },
	{ "__tracepoint_ext4_unlink_exit",
	  (void *)&klpe___tracepoint_ext4_unlink_exit, "ext4" },
	{ "ext4_orphan_add", (void *)&klpe_ext4_orphan_add, "ext4" },
	{ "__ext4_warning_inode", (void *)&klpe___ext4_warning_inode, "ext4" },
	{ "ext4_mark_inode_dirty", (void *)&klpe_ext4_mark_inode_dirty,
	  "ext4" },
	{ "__ext4_journal_start_sb", (void *)&klpe___ext4_journal_start_sb,
	  "ext4" },
	{ "__ext4_journal_stop", (void *)&klpe___ext4_journal_stop, "ext4" },
	{ "ext4_find_entry", (void *)&klpe_ext4_find_entry, "ext4" },
	{ "ext4_delete_entry", (void *)&klpe_ext4_delete_entry, "ext4" },
};

static int livepatch_bsc1173869_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1173869_module_nb = {
	.notifier_call = livepatch_bsc1173869_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1173869_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1173869_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1173869_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1173869_module_nb);
}
