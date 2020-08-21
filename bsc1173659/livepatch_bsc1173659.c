/*
 * livepatch_bsc1173659
 *
 * Fix for CVE-2019-16746, bsc#1173659
 *
 *  Upstream commits:
 *  0f3b07f027f8 ("cfg80211: add and use strongly typed element iteration
 *                 macros")
 *  3e48be05f3c7 ("netlink: add attribute range validation to policy")
 *  33188bd6430e ("netlink: add validation function to policy")
 *  f88eb7c0d002 ("nl80211: validate beacon head")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  none yet
 *
 *  SLE12-SP4 and SLE15 (i.e. cve/linux-4.12) commits:
 *  8511576560df57b8176581f85ea8c65504a81ca6
 *  cede1e049588339afaed1b5a367d4f13b49dea22
 *  ee0b40d724039e58320d1e7a06157f7204439535
 *  b032bc8734a28e9483d6b07617328e83f91644c4
 *
 *  SLE12-SP5 and SLE15-SP1 commits:
 *  8511576560df57b8176581f85ea8c65504a81ca6
 *  adebfa26c2229bd271a7a96965894314bce1a26a
 *  3f3917051206425a618cb9395f7e9aa100fba521
 *  d33ba46fa72cae16204a6be7b6a837872ef15afc
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

#if IS_ENABLED(CONFIG_CFG80211)

#if !IS_MODULE(CONFIG_CFG80211)
#error "Live patch supports only CONFIG_CFG80211=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1173659.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "cfg80211"


/* klp-ccp: from net/wireless/nl80211.c */
#include <linux/if.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/if_ether.h>
#include <linux/ieee80211.h>
#include <linux/nl80211.h>

/* klp-ccp: from net/wireless/nl80211.c */
#include <linux/netlink.h>
#include <linux/etherdevice.h>
#include <net/net_namespace.h>
#include <net/genetlink.h>
#include <net/cfg80211.h>
/* klp-ccp: from net/wireless/core.h */
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/rbtree.h>
#include <linux/debugfs.h>
#include <linux/workqueue.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>
#include <net/cfg80211.h>
/* klp-ccp: from net/wireless/rdev-ops.h */
#include <linux/rtnetlink.h>
#include <net/cfg80211.h>

/* klp-ccp: from include/linux/ieee80211.h */
/* New */
struct element {
	u8 id;
	u8 datalen;
	u8 data[];
};

/* New */
#define klpp_for_each_element(element, _data, _datalen)			\
	for (element = (void *)(_data);					\
	     (u8 *)(_data) + (_datalen) - (u8 *)element >=		\
		sizeof(*element) &&					\
	     (u8 *)(_data) + (_datalen) - (u8 *)element >=		\
		sizeof(*element) + element->datalen;			\
	     element = (void *)(element->data + element->datalen))

/* New */
static inline bool klpp_for_each_element_completed(const struct element *element,
					      const void *data, size_t datalen)
{
	return (u8 *)element == (u8 *)data + datalen;
}

/* klp-ccp: from include/net/cfg80211.h */
static unsigned int __attribute_const__ (*klpe_ieee80211_hdrlen)(__le16 fc);

/* klp-ccp: from net/wireless/nl80211.c */
/* New */
static int klpp_validate_beacon_head(const struct nlattr *attr)
{
	const u8 *data = nla_data(attr);
	unsigned int len = nla_len(attr);
	const struct element *elem;
	const struct ieee80211_mgmt *mgmt = (void *)data;
	unsigned int fixedlen = offsetof(struct ieee80211_mgmt,
					 u.beacon.variable);

	if (len < fixedlen)
		goto err;

	if ((*klpe_ieee80211_hdrlen)(mgmt->frame_control) !=
	    offsetof(struct ieee80211_mgmt, u.beacon))
		goto err;

	data += fixedlen;
	len -= fixedlen;

	klpp_for_each_element(elem, data, len) {
		/* nothing */
	}

	if (klpp_for_each_element_completed(elem, data, len))
		return 0;

err:
	return -EINVAL;
}

static bool (*klpe_is_valid_ie_attr)(const struct nlattr *attr);

int klpp_nl80211_parse_beacon(struct nlattr *attrs[],
				struct cfg80211_beacon_data *bcn)
{
	bool haveinfo = false;

	if (!(*klpe_is_valid_ie_attr)(attrs[NL80211_ATTR_BEACON_TAIL]) ||
	    !(*klpe_is_valid_ie_attr)(attrs[NL80211_ATTR_IE]) ||
	    !(*klpe_is_valid_ie_attr)(attrs[NL80211_ATTR_IE_PROBE_RESP]) ||
	    !(*klpe_is_valid_ie_attr)(attrs[NL80211_ATTR_IE_ASSOC_RESP]))
		return -EINVAL;

	memset(bcn, 0, sizeof(*bcn));

	if (attrs[NL80211_ATTR_BEACON_HEAD]) {
		/*
		 * Fix CVE-2019-16746
		 *  +2 lines
		 */
		if (klpp_validate_beacon_head(attrs[NL80211_ATTR_BEACON_HEAD]))
			return -EINVAL;

		bcn->head = nla_data(attrs[NL80211_ATTR_BEACON_HEAD]);
		bcn->head_len = nla_len(attrs[NL80211_ATTR_BEACON_HEAD]);
		if (!bcn->head_len)
			return -EINVAL;
		haveinfo = true;
	}

	if (attrs[NL80211_ATTR_BEACON_TAIL]) {
		bcn->tail = nla_data(attrs[NL80211_ATTR_BEACON_TAIL]);
		bcn->tail_len = nla_len(attrs[NL80211_ATTR_BEACON_TAIL]);
		haveinfo = true;
	}

	if (!haveinfo)
		return -EINVAL;

	if (attrs[NL80211_ATTR_IE]) {
		bcn->beacon_ies = nla_data(attrs[NL80211_ATTR_IE]);
		bcn->beacon_ies_len = nla_len(attrs[NL80211_ATTR_IE]);
	}

	if (attrs[NL80211_ATTR_IE_PROBE_RESP]) {
		bcn->proberesp_ies =
			nla_data(attrs[NL80211_ATTR_IE_PROBE_RESP]);
		bcn->proberesp_ies_len =
			nla_len(attrs[NL80211_ATTR_IE_PROBE_RESP]);
	}

	if (attrs[NL80211_ATTR_IE_ASSOC_RESP]) {
		bcn->assocresp_ies =
			nla_data(attrs[NL80211_ATTR_IE_ASSOC_RESP]);
		bcn->assocresp_ies_len =
			nla_len(attrs[NL80211_ATTR_IE_ASSOC_RESP]);
	}

	if (attrs[NL80211_ATTR_PROBE_RESP]) {
		bcn->probe_resp = nla_data(attrs[NL80211_ATTR_PROBE_RESP]);
		bcn->probe_resp_len = nla_len(attrs[NL80211_ATTR_PROBE_RESP]);
	}

	return 0;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "is_valid_ie_attr", (void *)&klpe_is_valid_ie_attr, "cfg80211" },
	{ "ieee80211_hdrlen", (void *)&klpe_ieee80211_hdrlen, "cfg80211" },
};

static int livepatch_bsc1173659_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1173659_module_nb = {
	.notifier_call = livepatch_bsc1173659_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1173659_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1173659_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1173659_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1173659_module_nb);
}

#endif /* IS_ENABLED(CONFIG_CFG80211) */
