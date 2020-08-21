/*
 * livepatch_bsc1173942
 *
 * Fix for CVE-2020-11668, bsc#1173942
 *
 *  Upstream commit:
 *  a246b4d54770 ("media: xirlink_cit: add missing descriptor sanity checks")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  none yet
 *
 *  SLE15 commit:
 *  none yet
 *
 *  SLE12-SP4, SLE12-SP5, and SLE15-SP1 commit:
 *  4e37700e17bba055d842ebcca91ee5f233c819de
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

#if IS_ENABLED(CONFIG_USB_GSPCA_XIRLINK_CIT)

#if !IS_MODULE(CONFIG_USB_GSPCA_XIRLINK_CIT)
#error "Live patch supports only CONFIG_USB_GSPCA_XIRLINK_CIT=m"
#endif

#define LIVEPATCHED_MODULE "gspca_xirlink_cit"

/* klp-ccp: from drivers/media/usb/gspca/xirlink_cit.c */
#define pr_fmt(fmt) LIVEPATCHED_MODULE ": " fmt


#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1173942.h"
#include "../kallsyms_relocs.h"


/* klp-ccp: from drivers/media/usb/gspca/xirlink_cit.c */
#include <linux/input.h>

/* klp-ccp: from drivers/media/usb/gspca/gspca.h */
#include <linux/kernel.h>
#include <linux/usb.h>

/* klp-ccp: from include/linux/usb.h */
#ifdef __KERNEL__

static struct usb_interface *(*klpe_usb_ifnum_to_if)(const struct usb_device *dev,
		unsigned ifnum);
static struct usb_host_interface *(*klpe_usb_altnum_to_altsetting)(
		const struct usb_interface *intf, unsigned int altnum);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif  /* __KERNEL__ */

/* klp-ccp: from drivers/media/usb/gspca/gspca.h */
#include <linux/videodev2.h>
#include <media/v4l2-common.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <linux/mutex.h>

#define GSPCA_MAX_FRAMES 16	/* maximum number of video frame buffers */

#define MAX_NURBS 4		/* max number of URBs */

struct cam {
	const struct v4l2_pix_format *cam_mode;	/* size nmodes */
	const struct framerates *mode_framerates; /* must have size nmodes,
						   * just like cam_mode */
	u32 bulk_size;		/* buffer size when image transfer by bulk */
	u32 input_flags;	/* value for ENUM_INPUT status flags */
	u8 nmodes;		/* size of cam_mode */
	u8 no_urb_create;	/* don't create transfer URBs */
	u8 bulk_nurbs;		/* number of URBs in bulk mode
				 * - cannot be > MAX_NURBS
				 * - when 0 and bulk_size != 0 means
				 *   1 URB and submit done by subdriver */
	u8 bulk;		/* image transfer by 0:isoc / 1:bulk */
	u8 npkt;		/* number of packets in an ISOC message
				 * 0 is the default value: 32 packets */
	u8 needs_full_bandwidth;/* Set this flag to notify the bandwidth calc.
				 * code that the cam fills all image buffers to
				 * the max, even when using compression. */
};

struct gspca_frame {
	__u8 *data;			/* frame buffer */
	int vma_use_count;
	struct v4l2_buffer v4l2_buf;
};

struct gspca_dev {
	struct video_device vdev;	/* !! must be the first item */
	struct module *module;		/* subdriver handling the device */
	struct v4l2_device v4l2_dev;
	struct usb_device *dev;
	struct file *capt_file;		/* file doing video capture */

#if IS_ENABLED(CONFIG_INPUT)
	struct input_dev *input_dev;
	char phys[64];			/* physical device path */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct cam cam;				/* device information */
	const struct sd_desc *sd_desc;		/* subdriver description */
	struct v4l2_ctrl_handler ctrl_handler;

	/* autogain and exposure or gain control cluster, these are global as
	   the autogain/exposure functions in autogain_functions.c use them */
	struct {
		struct v4l2_ctrl *autogain;
		struct v4l2_ctrl *exposure;
		struct v4l2_ctrl *gain;
		int exp_too_low_cnt, exp_too_high_cnt;
	};

	__u8 *usb_buf;				/* buffer for USB exchanges */
	struct urb *urb[MAX_NURBS];
#if IS_ENABLED(CONFIG_INPUT)
	struct urb *int_urb;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	__u8 *frbuf;				/* buffer for nframes */
	struct gspca_frame frame[GSPCA_MAX_FRAMES];
	u8 *image;				/* image beeing filled */
	__u32 frsz;				/* frame size */
	u32 image_len;				/* current length of image */
	atomic_t fr_q;				/* next frame to queue */
	atomic_t fr_i;				/* frame being filled */
	signed char fr_queue[GSPCA_MAX_FRAMES];	/* frame queue */
	char nframes;				/* number of frames */
	u8 fr_o;				/* next frame to dequeue */
	__u8 last_packet_type;
	__s8 empty_packet;		/* if (-1) don't check empty packets */
	__u8 streaming;			/* protected by both mutexes (*) */

	__u8 curr_mode;			/* current camera mode */
	struct v4l2_pix_format pixfmt;	/* current mode parameters */
	__u32 sequence;			/* frame sequence number */

	wait_queue_head_t wq;		/* wait queue */
	struct mutex usb_lock;		/* usb exchange protection */
	struct mutex queue_lock;	/* ISOC queue protection */
	int usb_err;			/* USB error - protected by usb_lock */
	u16 pkt_size;			/* ISOC packet size */
#ifdef CONFIG_PM
	char frozen;			/* suspend - resume */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	char present;			/* device connected */
	char nbufread;			/* number of buffers for read() */
	char memory;			/* memory type (V4L2_MEMORY_xxx) */
	__u8 iface;			/* USB interface number */
	__u8 alt;			/* USB alternate setting */
	int xfer_ep;			/* USB transfer endpoint address */
	u8 audio;			/* presence of audio device */

	/* (*) These variables are proteced by both usb_lock and queue_lock,
	   that is any code setting them is holding *both*, which means that
	   any code getting them needs to hold at least one of them */

	void *suse_kabi_padding;
};

/* klp-ccp: from drivers/media/usb/gspca/xirlink_cit.c */
int klpp_cit_get_packet_size(struct gspca_dev *gspca_dev)
{
	struct usb_host_interface *alt;
	struct usb_interface *intf;

	intf = (*klpe_usb_ifnum_to_if)(gspca_dev->dev, gspca_dev->iface);
	alt = (*klpe_usb_altnum_to_altsetting)(intf, gspca_dev->alt);
	if (!alt) {
		pr_err("Couldn't get altsetting\n");
		return -EIO;
	}

	/*
	 * Fix CVE-2020-11668
	 *  +3 lines
	 */
	if (alt->desc.bNumEndpoints < 1)
		return -ENODEV;

	return le16_to_cpu(alt->endpoint[0].desc.wMaxPacketSize);
}

int klpp_sd_isoc_init(struct gspca_dev *gspca_dev)
{
	/*
	 * Fix CVE-2020-11668
	 *  +1 line
	 */
	struct usb_interface_cache *intfc;
	struct usb_host_interface *alt;
	int max_packet_size;

	switch (gspca_dev->pixfmt.width) {
	case 160:
		max_packet_size = 450;
		break;
	case 176:
		max_packet_size = 600;
		break;
	default:
		max_packet_size = 1022;
		break;
	}

	/*
	 * Fix CVE-2020-11668
	 *  +10 lines
	 */
	intfc = gspca_dev->dev->actconfig->intf_cache[0];

	if (intfc->num_altsetting < 2)
		return -ENODEV;

	alt = &intfc->altsetting[1];

	if (alt->desc.bNumEndpoints < 1)
		return -ENODEV;

	/* Start isoc bandwidth "negotiation" at max isoc bandwidth */
	/*
	 * Fix CVE-2020-11668
	 *  -1 line
	 */
	alt->endpoint[0].desc.wMaxPacketSize = cpu_to_le16(max_packet_size);

	return 0;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "usb_ifnum_to_if", (void *)&klpe_usb_ifnum_to_if, "usbcore" },
	{ "usb_altnum_to_altsetting", (void *)&klpe_usb_altnum_to_altsetting,
	  "usbcore" },
};

static int livepatch_bsc1173942_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1173942_module_nb = {
	.notifier_call = livepatch_bsc1173942_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1173942_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1173942_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1173942_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1173942_module_nb);
}

#endif /* IS_ENABLED(CONFIG_USB_GSPCA_XIRLINK_CIT) */
