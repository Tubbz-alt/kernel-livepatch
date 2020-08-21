/*
 * livepatch_bsc1173934
 *
 * Fix for CVE-2019-15117, bsc#1173934
 *
 *  Upstream commit:
 *  daac07156b33 ("ALSA: usb-audio: Fix an OOB bug in parse_audio_mixer_unit")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  b7cf0ba5496d16bff97cf60af7496c1f8d864522
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  edfe3c90b22c1b1f09d77b27707e9c1b6b4dc523
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

#if IS_ENABLED(CONFIG_SND_USB_AUDIO)

#if !IS_MODULE(CONFIG_SND_USB_AUDIO)
#error "Live patch supports only CONFIG_SND_USB_AUDIO=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1173934.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "snd_usb_audio"


/* klp-ccp: from sound/usb/mixer.c */
#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/log2.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/usb.h>
#include <linux/usb/audio.h>
#include <sound/control.h>

/* klp-ccp: from include/sound/control.h */
static struct snd_kcontrol *(*klpe_snd_ctl_new1)(const struct snd_kcontrol_new * kcontrolnew, void * private_data);

/* klp-ccp: from sound/usb/mixer.c */
#include <sound/info.h>
#include <sound/tlv.h>

/* klp-ccp: from sound/usb/usbaudio.h */
struct snd_usb_audio {
	int index;
	struct usb_device *dev;
	struct snd_card *card;
	struct usb_interface *pm_intf;
	u32 usb_id;
	struct mutex mutex;
	unsigned int autosuspended:1;	
	atomic_t active;
	atomic_t shutdown;
	atomic_t usage_count;
	wait_queue_head_t shutdown_wait;
	unsigned int txfr_quirk:1; /* Subframe boundaries on transfers */
	unsigned int tx_length_quirk:1; /* Put length specifier in transfers */
	
	int num_interfaces;
	int num_suspended_intf;
	int sample_rate_read_error;

	int badd_profile;		/* UAC3 BADD profile */

	struct list_head pcm_list;	/* list of pcm streams */
	struct list_head ep_list;	/* list of audio-related endpoints */
	int pcm_devs;

	struct list_head midi_list;	/* list of midi interfaces */

	struct list_head mixer_list;	/* list of mixer interfaces */

	int setup;			/* from the 'device_setup' module param */
	bool autoclock;			/* from the 'autoclock' module param */
	bool keep_iface;		/* keep interface/altset after closing
					 * or parameter change
					 */

	struct usb_host_interface *ctrl_intf;	/* the audio control interface */
};

#define usb_audio_err(chip, fmt, args...) \
	dev_err(&(chip)->dev->dev, fmt, ##args)

#define usb_audio_dbg(chip, fmt, args...) \
	dev_dbg(&(chip)->dev->dev, fmt, ##args)

/* klp-ccp: from sound/usb/mixer.h */
struct usb_mixer_interface {
	struct snd_usb_audio *chip;
	struct usb_host_interface *hostif;
	struct list_head list;
	unsigned int ignore_ctl_error;
	struct urb *urb;
	/* array[MAX_ID_ELEMS], indexed by unit id */
	struct usb_mixer_elem_list **id_elems;

	/* the usb audio specification version this interface complies to */
	int protocol;

	/* Sound Blaster remote control stuff */
	const struct rc_config *rc_cfg;
	u32 rc_code;
	wait_queue_head_t rc_waitq;
	struct urb *rc_urb;
	struct usb_ctrlrequest *rc_setup_packet;
	u8 rc_buffer[6];

	bool disconnected;
};

#define MAX_CHANNELS	16	/* max logical channels */

enum {
	USB_MIXER_BOOLEAN,
	USB_MIXER_INV_BOOLEAN,
	USB_MIXER_S8,
	USB_MIXER_U8,
	USB_MIXER_S16,
	USB_MIXER_U16,
	USB_MIXER_S32,
	USB_MIXER_U32,
};

typedef void (*usb_mixer_elem_dump_func_t)(struct snd_info_buffer *buffer,
					 struct usb_mixer_elem_list *list);
typedef int (*usb_mixer_elem_resume_func_t)(struct usb_mixer_elem_list *elem);

struct usb_mixer_elem_list {
	struct usb_mixer_interface *mixer;
	struct usb_mixer_elem_list *next_id_elem; /* list of controls with same id */
	struct snd_kcontrol *kctl;
	unsigned int id;
	usb_mixer_elem_dump_func_t dump;
	usb_mixer_elem_resume_func_t resume;
};

struct usb_mixer_elem_info {
	struct usb_mixer_elem_list head;
	unsigned int control;	/* CS or ICN (high byte) */
	unsigned int cmask; /* channel mask bitmap: 0 = master */
	unsigned int idx_off; /* Control index offset */
	unsigned int ch_readonly;
	unsigned int master_readonly;
	int channels;
	int val_type;
	int min, max, res;
	int dBmin, dBmax;
	int cached;
	int cache_val[MAX_CHANNELS];
	u8 initialized;
	u8 min_mute;
	void *private_data;
};

static int (*klpe_snd_usb_mixer_add_control)(struct usb_mixer_elem_list *list,
			      struct snd_kcontrol *kctl);

static void (*klpe_snd_usb_mixer_elem_init_std)(struct usb_mixer_elem_list *list,
				 struct usb_mixer_interface *mixer,
				 int unitid);

static void (*klpe_snd_usb_mixer_elem_free)(struct snd_kcontrol *kctl);

/* klp-ccp: from sound/usb/mixer.c */
#define MAX_ID_ELEMS	256

struct usb_audio_term {
	int id;
	int type;
	int channels;
	unsigned int chconfig;
	int name;
};

struct mixer_build {
	struct snd_usb_audio *chip;
	struct usb_mixer_interface *mixer;
	unsigned char *buffer;
	unsigned int buflen;
	DECLARE_BITMAP(unitbitmap, MAX_ID_ELEMS);
	DECLARE_BITMAP(termbitmap, MAX_ID_ELEMS);
	struct usb_audio_term oterm;
	const struct usbmix_name_map *map;
	const struct usbmix_selector_map *selector_map;
};

/* klp-ccp: from sound/usb/mixer_maps.c */
struct usbmix_name_map {
	int id;
	const char *name;
	int control;
	struct usbmix_dB_map *dB;
};

/* klp-ccp: from sound/usb/mixer.c */
static const struct usbmix_name_map *
find_map(const struct usbmix_name_map *p, int unitid, int control)
{
	if (!p)
		return NULL;

	for (; p->id; p++) {
		if (p->id == unitid &&
		    (!control || !p->control || control == p->control))
			return p;
	}
	return NULL;
}

static int
check_mapped_name(const struct usbmix_name_map *p, char *buf, int buflen)
{
	if (!p || !p->name)
		return 0;

	buflen--;
	return strlcpy(buf, p->name, buflen);
}

static inline int
check_ignored_ctl(const struct usbmix_name_map *p)
{
	if (!p || p->name || p->dB)
		return 0;
	return 1;
}

static int (*klpe_parse_audio_unit)(struct mixer_build *state, int unitid);

static int check_matrix_bitmap(unsigned char *bmap,
			       int ich, int och, int num_outs)
{
	int idx = ich * num_outs + och;
	return bmap[idx >> 3] & (0x80 >> (idx & 7));
}

static int (*klpe_get_term_name)(struct snd_usb_audio *chip, struct usb_audio_term *iterm,
			 unsigned char *name, int maxlen, int term_only);

static int (*klpe_uac_mixer_unit_get_channels)(struct mixer_build *state,
				       struct uac_mixer_unit_descriptor *desc);

static int (*klpe_check_input_term)(struct mixer_build *state, int id,
			    struct usb_audio_term *term);

static int (*klpe_get_min_max_with_quirks)(struct usb_mixer_elem_info *cval,
				   int default_min, struct snd_kcontrol *kctl);

static struct snd_kcontrol_new (*klpe_usb_feature_unit_ctl);

static size_t append_ctl_name(struct snd_kcontrol *kctl, const char *str)
{
	return strlcat(kctl->id.name, str, sizeof(kctl->id.name));
}

static bool mixer_bitmap_overflow(struct uac_mixer_unit_descriptor *desc,
				  int protocol, int num_ins, int num_outs)
{
	u8 *hdr = (u8 *)desc;
	u8 *c = uac_mixer_unit_bmControls(desc, protocol);
	size_t rest; /* remaining bytes after bmMixerControls */

	switch (protocol) {
	case UAC_VERSION_1:
	default:
		rest = 1; /* iMixer */
		break;
	case UAC_VERSION_2:
		rest = 2; /* bmControls + iMixer */
		break;
	case UAC_VERSION_3:
		rest = 6; /* bmControls + wMixerDescrStr */
		break;
	}

	/* overflow? */
	return c + (num_ins * num_outs + 7) / 8 + rest > hdr + hdr[0];
}

static void klpr_build_mixer_unit_ctl(struct mixer_build *state,
				 struct uac_mixer_unit_descriptor *desc,
				 int in_pin, int in_ch, int num_outs,
				 int unitid, struct usb_audio_term *iterm)
{
	struct usb_mixer_elem_info *cval;
	unsigned int i, len;
	struct snd_kcontrol *kctl;
	const struct usbmix_name_map *map;

	map = find_map(state->map, unitid, 0);
	if (check_ignored_ctl(map))
		return;

	cval = kzalloc(sizeof(*cval), GFP_KERNEL);
	if (!cval)
		return;

	(*klpe_snd_usb_mixer_elem_init_std)(&cval->head, state->mixer, unitid);
	cval->control = in_ch + 1; /* based on 1 */
	cval->val_type = USB_MIXER_S16;
	for (i = 0; i < num_outs; i++) {
		__u8 *c = uac_mixer_unit_bmControls(desc, state->mixer->protocol);

		if (check_matrix_bitmap(c, in_ch, i, num_outs)) {
			cval->cmask |= (1 << i);
			cval->channels++;
		}
	}

	/* get min/max values */
	(*klpe_get_min_max_with_quirks)(cval, 0, ((void *)0));

	kctl = (*klpe_snd_ctl_new1)(&(*klpe_usb_feature_unit_ctl), cval);
	if (!kctl) {
		usb_audio_err(state->chip, "cannot malloc kcontrol\n");
		kfree(cval);
		return;
	}
	kctl->private_free = (*klpe_snd_usb_mixer_elem_free);

	len = check_mapped_name(map, kctl->id.name, sizeof(kctl->id.name));
	if (!len)
		len = (*klpe_get_term_name)(state->chip, iterm, kctl->id.name,
				    sizeof(kctl->id.name), 0);
	if (!len)
		len = sprintf(kctl->id.name, "Mixer Source %d", in_ch + 1);
	append_ctl_name(kctl, " Volume");

	usb_audio_dbg(state->chip, "[%d] MU [%s] ch = %d, val = %d/%d\n",
		    cval->head.id, kctl->id.name, cval->channels, cval->min, cval->max);
	(*klpe_snd_usb_mixer_add_control)(&cval->head, kctl);
}

int klpp_parse_audio_mixer_unit(struct mixer_build *state, int unitid,
				  void *raw_desc)
{
	struct uac_mixer_unit_descriptor *desc = raw_desc;
	struct usb_audio_term iterm;
	int input_pins, num_ins, num_outs;
	int pin, ich, err;

	err = (*klpe_uac_mixer_unit_get_channels)(state, desc);
	if (err < 0) {
		usb_audio_err(state->chip,
			      "invalid MIXER UNIT descriptor %d\n",
			      unitid);
		return err;
	}

	num_outs = err;
	input_pins = desc->bNrInPins;

	/*
	 * Fix CVE-2019-15117
	 *  +3 lines
	 */
	if (desc->bLength < sizeof(*desc) + desc->bNrInPins)
		return -EINVAL;

	num_ins = 0;
	ich = 0;
	for (pin = 0; pin < input_pins; pin++) {
		err = (*klpe_parse_audio_unit)(state, desc->baSourceID[pin]);
		if (err < 0)
			continue;
		/* no bmControls field (e.g. Maya44) -> ignore */
		if (!num_outs)
			continue;
		err = (*klpe_check_input_term)(state, desc->baSourceID[pin], &iterm);
		if (err < 0)
			return err;
		num_ins += iterm.channels;
		if (mixer_bitmap_overflow(desc, state->mixer->protocol,
					  num_ins, num_outs))
			break;
		for (; ich < num_ins; ich++) {
			int och, ich_has_controls = 0;

			for (och = 0; och < num_outs; och++) {
				__u8 *c = uac_mixer_unit_bmControls(desc,
						state->mixer->protocol);

				if (check_matrix_bitmap(c, ich, och, num_outs)) {
					ich_has_controls = 1;
					break;
				}
			}
			if (ich_has_controls)
				klpr_build_mixer_unit_ctl(state, desc, pin, ich, num_outs,
						     unitid, &iterm);
		}
	}
	return 0;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "usb_feature_unit_ctl", (void *)&klpe_usb_feature_unit_ctl,
	  "snd_usb_audio" },
	{ "snd_ctl_new1", (void *)&klpe_snd_ctl_new1, "snd" },
	{ "snd_usb_mixer_add_control", (void *)&klpe_snd_usb_mixer_add_control,
	  "snd_usb_audio" },
	{ "snd_usb_mixer_elem_init_std",
	  (void *)&klpe_snd_usb_mixer_elem_init_std, "snd_usb_audio" },
	{ "snd_usb_mixer_elem_free", (void *)&klpe_snd_usb_mixer_elem_free,
	  "snd_usb_audio" },
	{ "parse_audio_unit", (void *)&klpe_parse_audio_unit, "snd_usb_audio" },
	{ "get_term_name", (void *)&klpe_get_term_name, "snd_usb_audio" },
	{ "uac_mixer_unit_get_channels",
	  (void *)&klpe_uac_mixer_unit_get_channels, "snd_usb_audio" },
	{ "check_input_term", (void *)&klpe_check_input_term, "snd_usb_audio" },
	{ "get_min_max_with_quirks", (void *)&klpe_get_min_max_with_quirks,
	  "snd_usb_audio" },
};

static int livepatch_bsc1173934_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1173934_module_nb = {
	.notifier_call = livepatch_bsc1173934_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1173934_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1173934_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1173934_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1173934_module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND_USB_AUDIO) */
