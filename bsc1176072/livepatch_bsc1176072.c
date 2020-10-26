/*
 * livepatch_bsc1176072
 *
 * Fix for CVE-2020-14386, bsc#1176072
 *
 *  Upstream commit:
 *  acf69c946233 ("net/packet: fix overflow in tpacket_rcv")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  e97790c2992b7f4cc1ed81e38ee2a31cf9dcd092
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  8fbffb3b4a2158d8a2c421202df9ebe7b7299e7b
 *
 *  SLE15-SP2 commit:
 *  b3a3711d07804954a9466a21d7cb7ac28c0004ef
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

#if !IS_MODULE(CONFIG_PACKET)
#error "Live patch supports only CONFIG_PACKET=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1176072.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "af_packet"

/* klp-ccp: from net/packet/af_packet.c */
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_packet.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/if_vlan.h>
#include <linux/virtio_net.h>
#include <linux/net_tstamp.h>
#include <linux/percpu.h>
#include <linux/bpf.h>

/* klp-ccp: from net/packet/internal.h */
#include <linux/refcount.h>

struct tpacket_kbdq_core {
	struct pgv	*pkbdq;
	unsigned int	feature_req_word;
	unsigned int	hdrlen;
	unsigned char	reset_pending_on_curr_blk;
	unsigned char   delete_blk_timer;
	unsigned short	kactive_blk_num;
	unsigned short	blk_sizeof_priv;

	/* last_kactive_blk_num:
	 * trick to see if user-space has caught up
	 * in order to avoid refreshing timer when every single pkt arrives.
	 */
	unsigned short	last_kactive_blk_num;

	char		*pkblk_start;
	char		*pkblk_end;
	int		kblk_size;
	unsigned int	max_frame_len;
	unsigned int	knum_blocks;
	uint64_t	knxt_seq_num;
	char		*prev;
	char		*nxt_offset;
	struct sk_buff	*skb;

	atomic_t	blk_fill_in_prog;

	/* Default is set to 8ms */

	unsigned short  retire_blk_tov;
	unsigned short  version;
	unsigned long	tov_in_jiffies;

	/* timer to retire an outstanding block */
	struct timer_list retire_blk_timer;
};

struct pgv {
	char *buffer;
};

struct packet_ring_buffer {
	struct pgv		*pg_vec;

	unsigned int		head;
	unsigned int		frames_per_block;
	unsigned int		frame_size;
	unsigned int		frame_max;

	unsigned int		pg_vec_order;
	unsigned int		pg_vec_pages;
	unsigned int		pg_vec_len;

	unsigned int __percpu	*pending_refcnt;

	union {
		unsigned long			*rx_owner_map;
		struct tpacket_kbdq_core	prb_bdqc;
	};
};

struct packet_sock {
	/* struct sock has to be the first member of packet_sock */
	struct sock		sk;
	struct packet_fanout	*fanout;
	union  tpacket_stats_u	stats;
	struct packet_ring_buffer	rx_ring;
	struct packet_ring_buffer	tx_ring;
	int			copy_thresh;
	spinlock_t		bind_lock;
	struct mutex		pg_vec_lock;
	unsigned int		running;	/* bind_lock must be held */
	unsigned int		auxdata:1,	/* writer must hold sock lock */
				origdev:1,
				has_vnet_hdr:1,
				tp_loss:1,
				tp_tx_has_off:1;
	int			pressure;
	int			ifindex;	/* bound device		*/
	__be16			num;
	struct packet_rollover	*rollover;
	struct packet_mclist	*mclist;
	atomic_t		mapped;
	enum tpacket_versions	tp_version;
	unsigned int		tp_hdrlen;
	unsigned int		tp_reserve;
	unsigned int		tp_tstamp;
	struct completion	skb_completion;
	struct net_device __rcu	*cached_dev;
	int			(*xmit)(struct sk_buff *skb);
	struct packet_type	prot_hook ____cacheline_aligned_in_smp;
	atomic_t		tp_drops ____cacheline_aligned_in_smp;
};

static struct packet_sock *pkt_sk(struct sock *sk)
{
	return (struct packet_sock *)sk;
}

/* klp-ccp: from net/packet/af_packet.c */
union tpacket_uhdr {
	struct tpacket_hdr  *h1;
	struct tpacket2_hdr *h2;
	struct tpacket3_hdr *h3;
	void *raw;
};

#define V3_ALIGNMENT	(8)

#define BLOCK_STATUS(x)	((x)->hdr.bh1.block_status)
#define BLOCK_NUM_PKTS(x)	((x)->hdr.bh1.num_pkts)

#define BLOCK_LEN(x)		((x)->hdr.bh1.blk_len)

static void packet_increment_head(struct packet_ring_buffer *buff);
static int prb_curr_blk_in_use(struct tpacket_block_desc *);
static void *klpr_prb_dispatch_next_block(struct tpacket_kbdq_core *,
			struct packet_sock *);
static void (*klpe_prb_retire_current_block)(struct tpacket_kbdq_core *,
		struct packet_sock *, unsigned int status);
static int prb_queue_frozen(struct tpacket_kbdq_core *);
static void (*klpe_prb_open_block)(struct tpacket_kbdq_core *,
		struct tpacket_block_desc *);

static void prb_fill_rxhash(struct tpacket_kbdq_core *, struct tpacket3_hdr *);
static void prb_clear_rxhash(struct tpacket_kbdq_core *,
		struct tpacket3_hdr *);
static void prb_fill_vlan_info(struct tpacket_kbdq_core *,
		struct tpacket3_hdr *);

#define vio_le() virtio_legacy_is_little_endian()

#define GET_PBDQC_FROM_RB(x)	((struct tpacket_kbdq_core *)(&(x)->prb_bdqc))

#define GET_CURR_PBLOCK_DESC_FROM_CORE(x)	\
	((struct tpacket_block_desc *)((x)->pkbdq[(x)->kactive_blk_num].buffer))

static inline struct page * __pure pgv_to_page(void *addr)
{
	if (is_vmalloc_addr(addr))
		return vmalloc_to_page(addr);
	return virt_to_page(addr);
}

static void __packet_set_status(struct packet_sock *po, void *frame, int status)
{
	union tpacket_uhdr h;

	h.raw = frame;
	switch (po->tp_version) {
	case TPACKET_V1:
		h.h1->tp_status = status;
		flush_dcache_page(pgv_to_page(&h.h1->tp_status));
		break;
	case TPACKET_V2:
		h.h2->tp_status = status;
		flush_dcache_page(pgv_to_page(&h.h2->tp_status));
		break;
	case TPACKET_V3:
		h.h3->tp_status = status;
		flush_dcache_page(pgv_to_page(&h.h3->tp_status));
		break;
	default:
		WARN(1, "TPACKET version not supported.\n");
		BUG();
	}

	smp_wmb();
}

static int __packet_get_status(const struct packet_sock *po, void *frame)
{
	union tpacket_uhdr h;

	smp_rmb();

	h.raw = frame;
	switch (po->tp_version) {
	case TPACKET_V1:
		flush_dcache_page(pgv_to_page(&h.h1->tp_status));
		return h.h1->tp_status;
	case TPACKET_V2:
		flush_dcache_page(pgv_to_page(&h.h2->tp_status));
		return h.h2->tp_status;
	case TPACKET_V3:
		flush_dcache_page(pgv_to_page(&h.h3->tp_status));
		return h.h3->tp_status;
	default:
		WARN(1, "TPACKET version not supported.\n");
		BUG();
		return 0;
	}
}

static __u32 (*klpe_tpacket_get_timestamp)(struct sk_buff *skb, struct timespec *ts,
				   unsigned int flags);

static void *packet_lookup_frame(const struct packet_sock *po,
				 const struct packet_ring_buffer *rb,
				 unsigned int position,
				 int status)
{
	unsigned int pg_vec_pos, frame_offset;
	union tpacket_uhdr h;

	pg_vec_pos = position / rb->frames_per_block;
	frame_offset = position % rb->frames_per_block;

	h.raw = rb->pg_vec[pg_vec_pos].buffer +
		(frame_offset * rb->frame_size);

	if (status != __packet_get_status(po, h.raw))
		return NULL;

	return h.raw;
}

static void (*klpe_prb_open_block)(struct tpacket_kbdq_core *pkc1,
	struct tpacket_block_desc *pbd1);

static void prb_freeze_queue(struct tpacket_kbdq_core *pkc,
				  struct packet_sock *po)
{
	pkc->reset_pending_on_curr_blk = 1;
	po->stats.stats3.tp_freeze_q_cnt++;
}

#define TOTAL_PKT_LEN_INCL_ALIGN(length) (ALIGN((length), V3_ALIGNMENT))

static void *klpr_prb_dispatch_next_block(struct tpacket_kbdq_core *pkc,
		struct packet_sock *po)
{
	struct tpacket_block_desc *pbd;

	smp_rmb();

	/* 1. Get current block num */
	pbd = GET_CURR_PBLOCK_DESC_FROM_CORE(pkc);

	/* 2. If this block is currently in_use then freeze the queue */
	if (TP_STATUS_USER & BLOCK_STATUS(pbd)) {
		prb_freeze_queue(pkc, po);
		return NULL;
	}

	/*
	 * 3.
	 * open this block and return the offset where the first packet
	 * needs to get stored.
	 */
	(*klpe_prb_open_block)(pkc, pbd);
	return (void *)pkc->nxt_offset;
}

static void (*klpe_prb_retire_current_block)(struct tpacket_kbdq_core *pkc,
		struct packet_sock *po, unsigned int status);

static int prb_curr_blk_in_use(struct tpacket_block_desc *pbd)
{
	return TP_STATUS_USER & BLOCK_STATUS(pbd);
}

static int prb_queue_frozen(struct tpacket_kbdq_core *pkc)
{
	return pkc->reset_pending_on_curr_blk;
}

static void prb_clear_blk_fill_status(struct packet_ring_buffer *rb)
{
	struct tpacket_kbdq_core *pkc  = GET_PBDQC_FROM_RB(rb);
	atomic_dec(&pkc->blk_fill_in_prog);
}

static void prb_fill_rxhash(struct tpacket_kbdq_core *pkc,
			struct tpacket3_hdr *ppd)
{
	ppd->hv1.tp_rxhash = skb_get_hash(pkc->skb);
}

static void prb_clear_rxhash(struct tpacket_kbdq_core *pkc,
			struct tpacket3_hdr *ppd)
{
	ppd->hv1.tp_rxhash = 0;
}

static void prb_fill_vlan_info(struct tpacket_kbdq_core *pkc,
			struct tpacket3_hdr *ppd)
{
	if (skb_vlan_tag_present(pkc->skb)) {
		ppd->hv1.tp_vlan_tci = skb_vlan_tag_get(pkc->skb);
		ppd->hv1.tp_vlan_tpid = ntohs(pkc->skb->vlan_proto);
		ppd->tp_status = TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID;
	} else {
		ppd->hv1.tp_vlan_tci = 0;
		ppd->hv1.tp_vlan_tpid = 0;
		ppd->tp_status = TP_STATUS_AVAILABLE;
	}
}

static void prb_run_all_ft_ops(struct tpacket_kbdq_core *pkc,
			struct tpacket3_hdr *ppd)
{
	ppd->hv1.tp_padding = 0;
	prb_fill_vlan_info(pkc, ppd);

	if (pkc->feature_req_word & TP_FT_REQ_FILL_RXHASH)
		prb_fill_rxhash(pkc, ppd);
	else
		prb_clear_rxhash(pkc, ppd);
}

static void prb_fill_curr_block(char *curr,
				struct tpacket_kbdq_core *pkc,
				struct tpacket_block_desc *pbd,
				unsigned int len)
{
	struct tpacket3_hdr *ppd;

	ppd  = (struct tpacket3_hdr *)curr;
	ppd->tp_next_offset = TOTAL_PKT_LEN_INCL_ALIGN(len);
	pkc->prev = curr;
	pkc->nxt_offset += TOTAL_PKT_LEN_INCL_ALIGN(len);
	BLOCK_LEN(pbd) += TOTAL_PKT_LEN_INCL_ALIGN(len);
	BLOCK_NUM_PKTS(pbd) += 1;
	atomic_inc(&pkc->blk_fill_in_prog);
	prb_run_all_ft_ops(pkc, ppd);
}

static void *klpr___packet_lookup_frame_in_block(struct packet_sock *po,
					    struct sk_buff *skb,
					    unsigned int len
					    )
{
	struct tpacket_kbdq_core *pkc;
	struct tpacket_block_desc *pbd;
	char *curr, *end;

	pkc = GET_PBDQC_FROM_RB(&po->rx_ring);
	pbd = GET_CURR_PBLOCK_DESC_FROM_CORE(pkc);

	/* Queue is frozen when user space is lagging behind */
	if (prb_queue_frozen(pkc)) {
		/*
		 * Check if that last block which caused the queue to freeze,
		 * is still in_use by user-space.
		 */
		if (prb_curr_blk_in_use(pbd)) {
			/* Can't record this packet */
			return NULL;
		} else {
			/*
			 * Ok, the block was released by user-space.
			 * Now let's open that block.
			 * opening a block also thaws the queue.
			 * Thawing is a side effect.
			 */
			(*klpe_prb_open_block)(pkc, pbd);
		}
	}

	smp_mb();
	curr = pkc->nxt_offset;
	pkc->skb = skb;
	end = (char *)pbd + pkc->kblk_size;

	/* first try the current block */
	if (curr+TOTAL_PKT_LEN_INCL_ALIGN(len) < end) {
		prb_fill_curr_block(curr, pkc, pbd, len);
		return (void *)curr;
	}

	/* Ok, close the current block */
	(*klpe_prb_retire_current_block)(pkc, po, 0);

	/* Now, try to dispatch the next block */
	curr = (char *)klpr_prb_dispatch_next_block(pkc, po);
	if (curr) {
		pbd = GET_CURR_PBLOCK_DESC_FROM_CORE(pkc);
		prb_fill_curr_block(curr, pkc, pbd, len);
		return (void *)curr;
	}

	/*
	 * No free blocks are available.user_space hasn't caught up yet.
	 * Queue was just frozen and now this packet will get dropped.
	 */
	return NULL;
}

static void *klpr_packet_current_rx_frame(struct packet_sock *po,
					    struct sk_buff *skb,
					    int status, unsigned int len)
{
	char *curr = NULL;
	switch (po->tp_version) {
	case TPACKET_V1:
	case TPACKET_V2:
		curr = packet_lookup_frame(po, &po->rx_ring,
					po->rx_ring.head, status);
		return curr;
	case TPACKET_V3:
		return klpr___packet_lookup_frame_in_block(po, skb, len);
	default:
		WARN(1, "TPACKET version not supported\n");
		BUG();
		return NULL;
	}
}

static void packet_increment_rx_head(struct packet_sock *po,
					    struct packet_ring_buffer *rb)
{
	switch (po->tp_version) {
	case TPACKET_V1:
	case TPACKET_V2:
		return packet_increment_head(rb);
	case TPACKET_V3:
	default:
		WARN(1, "TPACKET version not supported.\n");
		BUG();
		return;
	}
}

static void packet_increment_head(struct packet_ring_buffer *buff)
{
	buff->head = buff->head != buff->frame_max ? buff->head+1 : 0;
}

#define ROOM_NONE	0x0

static int (*klpe___packet_rcv_has_room)(const struct packet_sock *po,
				 const struct sk_buff *skb);

static unsigned int run_filter(struct sk_buff *skb,
			       const struct sock *sk,
			       unsigned int res)
{
	struct sk_filter *filter;

	rcu_read_lock();
	filter = rcu_dereference(sk->sk_filter);
	if (filter != NULL)
		res = bpf_prog_run_clear_cb(filter->prog, skb);
	rcu_read_unlock();

	return res;
}

int klpp_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
		       struct packet_type *pt, struct net_device *orig_dev)
{
	struct sock *sk;
	struct packet_sock *po;
	struct sockaddr_ll *sll;
	union tpacket_uhdr h;
	u8 *skb_head = skb->data;
	int skb_len = skb->len;
	unsigned int snaplen, res;
	unsigned long status = TP_STATUS_USER;
	/*
	 * Fix CVE-2020-14386
	 *  -1 line, +2 lines
	 */
	unsigned short macoff, hdrlen;
	unsigned int netoff;
	struct sk_buff *copy_skb = NULL;
	struct timespec ts;
	__u32 ts_status;
	bool is_drop_n_account = false;
	unsigned int slot_id = 0;
	bool do_vnet = false;

	/* struct tpacket{2,3}_hdr is aligned to a multiple of TPACKET_ALIGNMENT.
	 * We may add members to them until current aligned size without forcing
	 * userspace to call getsockopt(..., PACKET_HDRLEN, ...).
	 */
	BUILD_BUG_ON(TPACKET_ALIGN(sizeof(*h.h2)) != 32);
	BUILD_BUG_ON(TPACKET_ALIGN(sizeof(*h.h3)) != 48);

	if (skb->pkt_type == PACKET_LOOPBACK)
		goto drop;

	sk = pt->af_packet_priv;
	po = pkt_sk(sk);

	if (!net_eq(dev_net(dev), sock_net(sk)))
		goto drop;

	if (dev->header_ops) {
		if (sk->sk_type != SOCK_DGRAM)
			skb_push(skb, skb->data - skb_mac_header(skb));
		else if (skb->pkt_type == PACKET_OUTGOING) {
			/* Special case: outgoing packets have ll header at head */
			skb_pull(skb, skb_network_offset(skb));
		}
	}

	snaplen = skb->len;

	res = run_filter(skb, sk, snaplen);
	if (!res)
		goto drop_n_restore;

	/* If we are flooded, just give up */
	if ((*klpe___packet_rcv_has_room)(po, skb) == ROOM_NONE) {
		atomic_inc(&po->tp_drops);
		goto drop_n_restore;
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		status |= TP_STATUS_CSUMNOTREADY;
	else if (skb->pkt_type != PACKET_OUTGOING &&
		 (skb->ip_summed == CHECKSUM_COMPLETE ||
		  skb_csum_unnecessary(skb)))
		status |= TP_STATUS_CSUM_VALID;

	if (snaplen > res)
		snaplen = res;

	if (sk->sk_type == SOCK_DGRAM) {
		macoff = netoff = TPACKET_ALIGN(po->tp_hdrlen) + 16 +
				  po->tp_reserve;
	} else {
		unsigned int maclen = skb_network_offset(skb);
		netoff = TPACKET_ALIGN(po->tp_hdrlen +
				       (maclen < 16 ? 16 : maclen)) +
				       po->tp_reserve;
		if (po->has_vnet_hdr) {
			netoff += sizeof(struct virtio_net_hdr);
			do_vnet = true;
		}
		macoff = netoff - maclen;
	}
	/*
	 * Fix CVE-2020-14386
	 *  +4 lines
	 */
	if (netoff > USHRT_MAX) {
		atomic_inc(&po->tp_drops);
		goto drop_n_restore;
	}
	if (po->tp_version <= TPACKET_V2) {
		if (macoff + snaplen > po->rx_ring.frame_size) {
			if (po->copy_thresh &&
			    atomic_read(&sk->sk_rmem_alloc) < sk->sk_rcvbuf) {
				if (skb_shared(skb)) {
					copy_skb = skb_clone(skb, GFP_ATOMIC);
				} else {
					copy_skb = skb_get(skb);
					skb_head = skb->data;
				}
				if (copy_skb)
					skb_set_owner_r(copy_skb, sk);
			}
			snaplen = po->rx_ring.frame_size - macoff;
			if ((int)snaplen < 0) {
				snaplen = 0;
				do_vnet = false;
			}
		}
	} else if (unlikely(macoff + snaplen >
			    GET_PBDQC_FROM_RB(&po->rx_ring)->max_frame_len)) {
		u32 nval;

		nval = GET_PBDQC_FROM_RB(&po->rx_ring)->max_frame_len - macoff;
		pr_err_once("tpacket_rcv: packet too big, clamped from %u to %u. macoff=%u\n",
			    snaplen, nval, macoff);
		snaplen = nval;
		if (unlikely((int)snaplen < 0)) {
			snaplen = 0;
			macoff = GET_PBDQC_FROM_RB(&po->rx_ring)->max_frame_len;
			do_vnet = false;
		}
	}
	spin_lock(&sk->sk_receive_queue.lock);
	h.raw = klpr_packet_current_rx_frame(po, skb,
					TP_STATUS_KERNEL, (macoff+snaplen));
	if (!h.raw)
		goto drop_n_account;

	if (po->tp_version <= TPACKET_V2) {
		slot_id = po->rx_ring.head;
		if (test_bit(slot_id, po->rx_ring.rx_owner_map))
			goto drop_n_account;
		__set_bit(slot_id, po->rx_ring.rx_owner_map);
	}

	if (do_vnet &&
	    virtio_net_hdr_from_skb(skb, h.raw + macoff -
				    sizeof(struct virtio_net_hdr),
				    vio_le(), true, 0))
		goto drop_n_account;

	if (po->tp_version <= TPACKET_V2) {
		packet_increment_rx_head(po, &po->rx_ring);
	/*
	 * LOSING will be reported till you read the stats,
	 * because it's COR - Clear On Read.
	 * Anyways, moving it for V1/V2 only as V3 doesn't need this
	 * at packet level.
	 */
		if (atomic_read(&po->tp_drops))
			status |= TP_STATUS_LOSING;
	}

	po->stats.stats1.tp_packets++;
	if (copy_skb) {
		status |= TP_STATUS_COPY;
		__skb_queue_tail(&sk->sk_receive_queue, copy_skb);
	}
	spin_unlock(&sk->sk_receive_queue.lock);

	skb_copy_bits(skb, 0, h.raw + macoff, snaplen);

	if (!(ts_status = (*klpe_tpacket_get_timestamp)(skb, &ts, po->tp_tstamp)))
		getnstimeofday(&ts);

	status |= ts_status;

	switch (po->tp_version) {
	case TPACKET_V1:
		h.h1->tp_len = skb->len;
		h.h1->tp_snaplen = snaplen;
		h.h1->tp_mac = macoff;
		h.h1->tp_net = netoff;
		h.h1->tp_sec = ts.tv_sec;
		h.h1->tp_usec = ts.tv_nsec / NSEC_PER_USEC;
		hdrlen = sizeof(*h.h1);
		break;
	case TPACKET_V2:
		h.h2->tp_len = skb->len;
		h.h2->tp_snaplen = snaplen;
		h.h2->tp_mac = macoff;
		h.h2->tp_net = netoff;
		h.h2->tp_sec = ts.tv_sec;
		h.h2->tp_nsec = ts.tv_nsec;
		if (skb_vlan_tag_present(skb)) {
			h.h2->tp_vlan_tci = skb_vlan_tag_get(skb);
			h.h2->tp_vlan_tpid = ntohs(skb->vlan_proto);
			status |= TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID;
		} else {
			h.h2->tp_vlan_tci = 0;
			h.h2->tp_vlan_tpid = 0;
		}
		memset(h.h2->tp_padding, 0, sizeof(h.h2->tp_padding));
		hdrlen = sizeof(*h.h2);
		break;
	case TPACKET_V3:
		/* tp_nxt_offset,vlan are already populated above.
		 * So DONT clear those fields here
		 */
		h.h3->tp_status |= status;
		h.h3->tp_len = skb->len;
		h.h3->tp_snaplen = snaplen;
		h.h3->tp_mac = macoff;
		h.h3->tp_net = netoff;
		h.h3->tp_sec  = ts.tv_sec;
		h.h3->tp_nsec = ts.tv_nsec;
		memset(h.h3->tp_padding, 0, sizeof(h.h3->tp_padding));
		hdrlen = sizeof(*h.h3);
		break;
	default:
		BUG();
	}

	sll = h.raw + TPACKET_ALIGN(hdrlen);
	sll->sll_halen = dev_parse_header(skb, sll->sll_addr);
	sll->sll_family = AF_PACKET;
	sll->sll_hatype = dev->type;
	sll->sll_protocol = skb->protocol;
	sll->sll_pkttype = skb->pkt_type;
	if (unlikely(po->origdev))
		sll->sll_ifindex = orig_dev->ifindex;
	else
		sll->sll_ifindex = dev->ifindex;

	smp_mb();

#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE == 1
	if (po->tp_version <= TPACKET_V2) {
		u8 *start, *end;

		end = (u8 *) PAGE_ALIGN((unsigned long) h.raw +
					macoff + snaplen);

		for (start = h.raw; start < end; start += PAGE_SIZE)
			flush_dcache_page(pgv_to_page(start));
	}
	smp_wmb();
#endif

	if (po->tp_version <= TPACKET_V2) {
		spin_lock(&sk->sk_receive_queue.lock);
		__packet_set_status(po, h.raw, status);
		__clear_bit(slot_id, po->rx_ring.rx_owner_map);
		spin_unlock(&sk->sk_receive_queue.lock);
		sk->sk_data_ready(sk);
	} else {
		prb_clear_blk_fill_status(&po->rx_ring);
	}

drop_n_restore:
	if (skb_head != skb->data && skb_shared(skb)) {
		skb->data = skb_head;
		skb->len = skb_len;
	}
drop:
	if (!is_drop_n_account)
		consume_skb(skb);
	else
		kfree_skb(skb);
	return 0;

drop_n_account:
	spin_unlock(&sk->sk_receive_queue.lock);
	atomic_inc(&po->tp_drops);
	is_drop_n_account = true;

	sk->sk_data_ready(sk);
	kfree_skb(copy_skb);
	goto drop_n_restore;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "prb_retire_current_block", (void *)&klpe_prb_retire_current_block,
	  "af_packet" },
	{ "prb_open_block", (void *)&klpe_prb_open_block, "af_packet" },
	{ "tpacket_get_timestamp", (void *)&klpe_tpacket_get_timestamp,
	  "af_packet" },
	{ "__packet_rcv_has_room", (void *)&klpe___packet_rcv_has_room,
	  "af_packet" },
};

static int livepatch_bsc1176072_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1176072_module_nb = {
	.notifier_call = livepatch_bsc1176072_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1176072_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1176072_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1176072_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1176072_module_nb);
}
