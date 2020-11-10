/*
 * livepatch_bsc1177729
 *
 * Fix for CVE-2020-12351, bsc#1177729
 *
 *  Upstream commit:
 *  f19425641cb2 ("Bluetooth: L2CAP: Fix calling sk_filter on non-socket based
 *                 channel")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  199fc71f7282b982480d2522705006d669dad6ee
 *
 *  SLE15-SP2 commit:
 *  f0ba0e32713bfc8260ea5c0598123bca058e6695
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

#if IS_ENABLED(CONFIG_BT)

#if !IS_MODULE(CONFIG_BT)
#error "Live patch supports only CONFIG_BT=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1177729.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "bluetooth"

/* klp-ccp: from net/bluetooth/l2cap_sock.c */
static const struct l2cap_ops (*klpe_l2cap_chan_ops);

/* klp-ccp: from net/bluetooth/l2cap_core.c */
#include <linux/module.h>
#include <linux/debugfs.h>

/* klp-ccp: from include/linux/crc16.h */
static u16 (*klpe_crc16)(u16 crc, const u8 *buffer, size_t len);

/* klp-ccp: from net/bluetooth/l2cap_core.c */
#include <linux/filter.h>
#include <net/bluetooth/bluetooth.h>

/* klp-ccp: from include/net/bluetooth/bluetooth.h */
static __printf(1, 2)
void (*klpe_bt_err)(const char *fmt, ...);

#define KLPR_BT_ERR(fmt, ...)	(*klpe_bt_err)(fmt "\n", ##__VA_ARGS__)

/* klp-ccp: from net/bluetooth/l2cap_core.c */
#include <net/bluetooth/l2cap.h>

/* klp-ccp: from include/net/bluetooth/l2cap.h */
static void (*klpe_l2cap_chan_put)(struct l2cap_chan *c);

static inline bool klpr_l2cap_clear_timer(struct l2cap_chan *chan,
				     struct delayed_work *work)
{
	bool ret;

	/* put(chan) if delayed work cancelled otherwise it
	   is done in delayed work function */
	ret = cancel_delayed_work(work);
	if (ret)
		(*klpe_l2cap_chan_put)(chan);

	return ret;
}

/* klp-ccp: from net/bluetooth/a2mp.h */
#include <net/bluetooth/l2cap.h>

#if IS_ENABLED(CONFIG_BT_HS)

static struct l2cap_chan *(*klpe_a2mp_channel_create)(struct l2cap_conn *conn,
				       struct sk_buff *skb);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from net/bluetooth/l2cap_core.c */
static void (*klpe_l2cap_send_disconn_req)(struct l2cap_chan *chan, int err);

static struct l2cap_chan *(*klpe_l2cap_get_chan_by_scid)(struct l2cap_conn *conn,
						 u16 cid);

static void __unpack_enhanced_control(u16 enh, struct l2cap_ctrl *control)
{
	control->reqseq = (enh & L2CAP_CTRL_REQSEQ) >> L2CAP_CTRL_REQSEQ_SHIFT;
	control->final = (enh & L2CAP_CTRL_FINAL) >> L2CAP_CTRL_FINAL_SHIFT;

	if (enh & L2CAP_CTRL_FRAME_TYPE) {
		/* S-Frame */
		control->sframe = 1;
		control->poll = (enh & L2CAP_CTRL_POLL) >> L2CAP_CTRL_POLL_SHIFT;
		control->super = (enh & L2CAP_CTRL_SUPERVISE) >> L2CAP_CTRL_SUPER_SHIFT;

		control->sar = 0;
		control->txseq = 0;
	} else {
		/* I-Frame */
		control->sframe = 0;
		control->sar = (enh & L2CAP_CTRL_SAR) >> L2CAP_CTRL_SAR_SHIFT;
		control->txseq = (enh & L2CAP_CTRL_TXSEQ) >> L2CAP_CTRL_TXSEQ_SHIFT;

		control->poll = 0;
		control->super = 0;
	}
}

static void __unpack_extended_control(u32 ext, struct l2cap_ctrl *control)
{
	control->reqseq = (ext & L2CAP_EXT_CTRL_REQSEQ) >> L2CAP_EXT_CTRL_REQSEQ_SHIFT;
	control->final = (ext & L2CAP_EXT_CTRL_FINAL) >> L2CAP_EXT_CTRL_FINAL_SHIFT;

	if (ext & L2CAP_EXT_CTRL_FRAME_TYPE) {
		/* S-Frame */
		control->sframe = 1;
		control->poll = (ext & L2CAP_EXT_CTRL_POLL) >> L2CAP_EXT_CTRL_POLL_SHIFT;
		control->super = (ext & L2CAP_EXT_CTRL_SUPERVISE) >> L2CAP_EXT_CTRL_SUPER_SHIFT;

		control->sar = 0;
		control->txseq = 0;
	} else {
		/* I-Frame */
		control->sframe = 0;
		control->sar = (ext & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
		control->txseq = (ext & L2CAP_EXT_CTRL_TXSEQ) >> L2CAP_EXT_CTRL_TXSEQ_SHIFT;

		control->poll = 0;
		control->super = 0;
	}
}

static inline void __unpack_control(struct l2cap_chan *chan,
				    struct sk_buff *skb)
{
	if (test_bit(FLAG_EXT_CTRL, &chan->flags)) {
		__unpack_extended_control(get_unaligned_le32(skb->data),
					  &bt_cb(skb)->l2cap);
		skb_pull(skb, L2CAP_EXT_CTRL_SIZE);
	} else {
		__unpack_enhanced_control(get_unaligned_le16(skb->data),
					  &bt_cb(skb)->l2cap);
		skb_pull(skb, L2CAP_ENH_CTRL_SIZE);
	}
}

static void klpr_l2cap_chan_ready(struct l2cap_chan *chan)
{
	/* The channel may have already been flagged as connected in
	 * case of receiving data before the L2CAP info req/rsp
	 * procedure is complete.
	 */
	if (chan->state == BT_CONNECTED)
		return;

	/* This clears all conf flags, including CONF_NOT_COMPLETE */
	chan->conf_state = 0;
	klpr_l2cap_clear_timer(chan, &chan->chan_timer);

	if (chan->mode == L2CAP_MODE_LE_FLOWCTL && !chan->tx_credits)
		chan->ops->suspend(chan);

	chan->state = BT_CONNECTED;

	chan->ops->ready(chan);
}

static void (*klpe_l2cap_send_disconn_req)(struct l2cap_chan *chan, int err);

static void (*klpe_l2cap_pass_to_tx)(struct l2cap_chan *chan,
			     struct l2cap_ctrl *control);

static int klpr_l2cap_check_fcs(struct l2cap_chan *chan,  struct sk_buff *skb)
{
	u16 our_fcs, rcv_fcs;
	int hdr_size;

	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
		hdr_size = L2CAP_EXT_HDR_SIZE;
	else
		hdr_size = L2CAP_ENH_HDR_SIZE;

	if (chan->fcs == L2CAP_FCS_CRC16) {
		skb_trim(skb, skb->len - L2CAP_FCS_SIZE);
		rcv_fcs = get_unaligned_le16(skb->data + skb->len);
		our_fcs = (*klpe_crc16)(0, skb->data - hdr_size, skb->len + hdr_size);

		if (our_fcs != rcv_fcs)
			return -EBADMSG;
	}
	return 0;
}

static void append_skb_frag(struct sk_buff *skb, struct sk_buff *new_frag,
			    struct sk_buff **last_frag)
{
	/* skb->len reflects data in skb as well as all fragments
	 * skb->data_len reflects only data in fragments
	 */
	if (!skb_has_frag_list(skb))
		skb_shinfo(skb)->frag_list = new_frag;

	new_frag->next = NULL;

	(*last_frag)->next = new_frag;
	*last_frag = new_frag;

	skb->len += new_frag->len;
	skb->data_len += new_frag->len;
	skb->truesize += new_frag->truesize;
}

static int (*klpe_l2cap_reassemble_sdu)(struct l2cap_chan *chan, struct sk_buff *skb,
				struct l2cap_ctrl *control);

static u8 (*klpe_l2cap_classify_txseq)(struct l2cap_chan *chan, u16 txseq);

static int (*klpe_l2cap_rx)(struct l2cap_chan *chan, struct l2cap_ctrl *control,
		    struct sk_buff *skb, u8 event);

static int klpr_l2cap_stream_rx(struct l2cap_chan *chan, struct l2cap_ctrl *control,
			   struct sk_buff *skb)
{
	BT_DBG("chan %p, control %p, skb %p, state %d", chan, control, skb,
	       chan->rx_state);

	if ((*klpe_l2cap_classify_txseq)(chan, control->txseq) ==
	    L2CAP_TXSEQ_EXPECTED) {
		(*klpe_l2cap_pass_to_tx)(chan, control);

		BT_DBG("buffer_seq %d->%d", chan->buffer_seq,
		       __next_seq(chan, chan->buffer_seq));

		chan->buffer_seq = __next_seq(chan, chan->buffer_seq);

		(*klpe_l2cap_reassemble_sdu)(chan, skb, control);
	} else {
		if (chan->sdu) {
			kfree_skb(chan->sdu);
			chan->sdu = NULL;
		}
		chan->sdu_last_frag = NULL;
		chan->sdu_len = 0;

		if (skb) {
			BT_DBG("Freeing %p", skb);
			kfree_skb(skb);
		}
	}

	chan->last_acked_seq = control->txseq;
	chan->expected_tx_seq = __next_seq(chan, control->txseq);

	return 0;
}

static int klpp_l2cap_data_rcv(struct l2cap_chan *chan, struct sk_buff *skb)
{
	struct l2cap_ctrl *control = &bt_cb(skb)->l2cap;
	u16 len;
	u8 event;

	__unpack_control(chan, skb);

	len = skb->len;

	/*
	 * We can just drop the corrupted I-frame here.
	 * Receiver will miss it and start proper recovery
	 * procedures and ask for retransmission.
	 */
	if (klpr_l2cap_check_fcs(chan, skb))
		goto drop;

	if (!control->sframe && control->sar == L2CAP_SAR_START)
		len -= L2CAP_SDULEN_SIZE;

	if (chan->fcs == L2CAP_FCS_CRC16)
		len -= L2CAP_FCS_SIZE;

	if (len > chan->mps) {
		(*klpe_l2cap_send_disconn_req)(chan, ECONNRESET);
		goto drop;
	}

	/*
	 * Fix CVE-2020-12351
	 *  -2 lines, +4 lines
	 */
	if ((chan->mode == L2CAP_MODE_ERTM ||
	     chan->mode == L2CAP_MODE_STREAMING) &&
	    chan->ops == &(*klpe_l2cap_chan_ops) &&
	    sk_filter(chan->data, skb))
		goto drop;

	if (!control->sframe) {
		int err;

		BT_DBG("iframe sar %d, reqseq %d, final %d, txseq %d",
		       control->sar, control->reqseq, control->final,
		       control->txseq);

		/* Validate F-bit - F=0 always valid, F=1 only
		 * valid in TX WAIT_F
		 */
		if (control->final && chan->tx_state != L2CAP_TX_STATE_WAIT_F)
			goto drop;

		if (chan->mode != L2CAP_MODE_STREAMING) {
			event = L2CAP_EV_RECV_IFRAME;
			err = (*klpe_l2cap_rx)(chan, control, skb, event);
		} else {
			err = klpr_l2cap_stream_rx(chan, control, skb);
		}

		if (err)
			(*klpe_l2cap_send_disconn_req)(chan, ECONNRESET);
	} else {
		const u8 rx_func_to_event[4] = {
			L2CAP_EV_RECV_RR, L2CAP_EV_RECV_REJ,
			L2CAP_EV_RECV_RNR, L2CAP_EV_RECV_SREJ
		};

		/* Only I-frames are expected in streaming mode */
		if (chan->mode == L2CAP_MODE_STREAMING)
			goto drop;

		BT_DBG("sframe reqseq %d, final %d, poll %d, super %d",
		       control->reqseq, control->final, control->poll,
		       control->super);

		if (len != 0) {
			KLPR_BT_ERR("Trailing bytes: %d in sframe", len);
			(*klpe_l2cap_send_disconn_req)(chan, ECONNRESET);
			goto drop;
		}

		/* Validate F and P bits */
		if (control->final && (control->poll ||
				       chan->tx_state != L2CAP_TX_STATE_WAIT_F))
			goto drop;

		event = rx_func_to_event[control->super];
		if ((*klpe_l2cap_rx)(chan, control, skb, event))
			(*klpe_l2cap_send_disconn_req)(chan, ECONNRESET);
	}

	return 0;

drop:
	kfree_skb(skb);
	return 0;
}

static void (*klpe_l2cap_chan_le_send_credits)(struct l2cap_chan *chan);

static int klpr_l2cap_le_data_rcv(struct l2cap_chan *chan, struct sk_buff *skb)
{
	int err;

	if (!chan->rx_credits) {
		KLPR_BT_ERR("No credits to receive LE L2CAP data");
		(*klpe_l2cap_send_disconn_req)(chan, ECONNRESET);
		return -ENOBUFS;
	}

	if (chan->imtu < skb->len) {
		KLPR_BT_ERR("Too big LE L2CAP PDU");
		return -ENOBUFS;
	}

	chan->rx_credits--;
	BT_DBG("rx_credits %u -> %u", chan->rx_credits + 1, chan->rx_credits);

	(*klpe_l2cap_chan_le_send_credits)(chan);

	err = 0;

	if (!chan->sdu) {
		u16 sdu_len;

		sdu_len = get_unaligned_le16(skb->data);
		skb_pull(skb, L2CAP_SDULEN_SIZE);

		BT_DBG("Start of new SDU. sdu_len %u skb->len %u imtu %u",
		       sdu_len, skb->len, chan->imtu);

		if (sdu_len > chan->imtu) {
			KLPR_BT_ERR("Too big LE L2CAP SDU length received");
			err = -EMSGSIZE;
			goto failed;
		}

		if (skb->len > sdu_len) {
			KLPR_BT_ERR("Too much LE L2CAP data received");
			err = -EINVAL;
			goto failed;
		}

		if (skb->len == sdu_len)
			return chan->ops->recv(chan, skb);

		chan->sdu = skb;
		chan->sdu_len = sdu_len;
		chan->sdu_last_frag = skb;

		/* Detect if remote is not able to use the selected MPS */
		if (skb->len + L2CAP_SDULEN_SIZE < chan->mps) {
			u16 mps_len = skb->len + L2CAP_SDULEN_SIZE;

			/* Adjust the number of credits */
			BT_DBG("chan->mps %u -> %u", chan->mps, mps_len);
			chan->mps = mps_len;
			(*klpe_l2cap_chan_le_send_credits)(chan);
		 }

		return 0;
	}

	BT_DBG("SDU fragment. chan->sdu->len %u skb->len %u chan->sdu_len %u",
	       chan->sdu->len, skb->len, chan->sdu_len);

	if (chan->sdu->len + skb->len > chan->sdu_len) {
		KLPR_BT_ERR("Too much LE L2CAP data received");
		err = -EINVAL;
		goto failed;
	}

	append_skb_frag(chan->sdu, skb, &chan->sdu_last_frag);
	skb = NULL;

	if (chan->sdu->len == chan->sdu_len) {
		err = chan->ops->recv(chan, chan->sdu);
		if (!err) {
			chan->sdu = NULL;
			chan->sdu_last_frag = NULL;
			chan->sdu_len = 0;
		}
	}

failed:
	if (err) {
		kfree_skb(skb);
		kfree_skb(chan->sdu);
		chan->sdu = NULL;
		chan->sdu_last_frag = NULL;
		chan->sdu_len = 0;
	}

	/* We can't return an error here since we took care of the skb
	 * freeing internally. An error return would cause the caller to
	 * do a double-free of the skb.
	 */
	return 0;
}

void klpp_l2cap_data_channel(struct l2cap_conn *conn, u16 cid,
			       struct sk_buff *skb)
{
	struct l2cap_chan *chan;

	chan = (*klpe_l2cap_get_chan_by_scid)(conn, cid);
	if (!chan) {
		if (cid == L2CAP_CID_A2MP) {
			chan = (*klpe_a2mp_channel_create)(conn, skb);
			if (!chan) {
				kfree_skb(skb);
				return;
			}

			l2cap_chan_lock(chan);
		} else {
			BT_DBG("unknown cid 0x%4.4x", cid);
			/* Drop packet and return */
			kfree_skb(skb);
			return;
		}
	}

	BT_DBG("chan %p, len %d", chan, skb->len);

	/* If we receive data on a fixed channel before the info req/rsp
	 * procdure is done simply assume that the channel is supported
	 * and mark it as ready.
	 */
	if (chan->chan_type == L2CAP_CHAN_FIXED)
		klpr_l2cap_chan_ready(chan);

	if (chan->state != BT_CONNECTED)
		goto drop;

	switch (chan->mode) {
	case L2CAP_MODE_LE_FLOWCTL:
		if (klpr_l2cap_le_data_rcv(chan, skb) < 0)
			goto drop;

		goto done;

	case L2CAP_MODE_BASIC:
		/* If socket recv buffers overflows we drop data here
		 * which is *bad* because L2CAP has to be reliable.
		 * But we don't have any other choice. L2CAP doesn't
		 * provide flow control mechanism. */

		if (chan->imtu < skb->len) {
			KLPR_BT_ERR("Dropping L2CAP data: receive buffer overflow");
			goto drop;
		}

		if (!chan->ops->recv(chan, skb))
			goto done;
		break;

	case L2CAP_MODE_ERTM:
	case L2CAP_MODE_STREAMING:
		klpp_l2cap_data_rcv(chan, skb);
		goto done;

	default:
		BT_DBG("chan %p: bad mode 0x%2.2x", chan, chan->mode);
		break;
	}

drop:
	kfree_skb(skb);

done:
	l2cap_chan_unlock(chan);
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "l2cap_chan_ops", (void *)&klpe_l2cap_chan_ops, "bluetooth" },
	{ "crc16", (void *)&klpe_crc16, "crc16" },
	{ "bt_err", (void *)&klpe_bt_err, "bluetooth" },
	{ "l2cap_chan_put", (void *)&klpe_l2cap_chan_put, "bluetooth" },
	{ "a2mp_channel_create", (void *)&klpe_a2mp_channel_create,
	  "bluetooth" },
	{ "l2cap_send_disconn_req", (void *)&klpe_l2cap_send_disconn_req,
	  "bluetooth" },
	{ "l2cap_get_chan_by_scid", (void *)&klpe_l2cap_get_chan_by_scid,
	  "bluetooth" },
	{ "l2cap_pass_to_tx", (void *)&klpe_l2cap_pass_to_tx, "bluetooth" },
	{ "l2cap_reassemble_sdu", (void *)&klpe_l2cap_reassemble_sdu,
	  "bluetooth" },
	{ "l2cap_classify_txseq", (void *)&klpe_l2cap_classify_txseq,
	  "bluetooth" },
	{ "l2cap_rx", (void *)&klpe_l2cap_rx, "bluetooth" },
	{ "l2cap_chan_le_send_credits",
	  (void *)&klpe_l2cap_chan_le_send_credits, "bluetooth" },
};

static int livepatch_bsc1177729_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1177729_module_nb = {
	.notifier_call = livepatch_bsc1177729_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1177729_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1177729_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1177729_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1177729_module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
