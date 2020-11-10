/*
 * livepatch_bsc1177513
 *
 * Fix for CVE-2020-25645, bsc#1177513
 *
 *  Upstream commit:
 *  34beb2159451 ("geneve: add transport ports in route lookup for geneve")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  1139e0ae8aec422d4646f6fecb8da4175ca27fef
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  e7568d7d32fc561a5a553b46ec73e6753be6b7fa
 *
 *  SLE15-SP2 commit:
 *  7ab9b466547c939c41aa7179c497d9fa0b98c61a
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

#if !IS_MODULE(CONFIG_GENEVE)
#error "Live patch supports only CONFIG_GENEVE=m"
#endif

#define LIVEPATCHED_MODULE "geneve"

/* klp-ccp: from drivers/net/geneve.c */
#define pr_fmt(fmt) LIVEPATCHED_MODULE ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/hash.h>
#include <net/ipv6_stubs.h>
#include <net/dst_metadata.h>
#include <net/gro_cells.h>
#include <net/rtnetlink.h>
#include <net/geneve.h>


#include "livepatch_bsc1177513.h"
#include "../kallsyms_relocs.h"


/* klp-ccp: from include/net/udp_tunnel.h */
static void (*klpe_udp_tunnel_xmit_skb)(struct rtable *rt, struct sock *sk, struct sk_buff *skb,
			 __be32 src, __be32 dst, __u8 tos, __u8 ttl,
			 __be16 df, __be16 src_port, __be16 dst_port,
			 bool xnet, bool nocheck);

#if IS_ENABLED(CONFIG_IPV6)
static int (*klpe_udp_tunnel6_xmit_skb)(struct dst_entry *dst, struct sock *sk,
			 struct sk_buff *skb,
			 struct net_device *dev, struct in6_addr *saddr,
			 struct in6_addr *daddr,
			 __u8 prio, __u8 ttl, __be32 label,
			 __be16 src_port, __be16 dst_port, bool nocheck);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from drivers/net/geneve.c */
#define VNI_HASH_BITS		10
#define VNI_HASH_SIZE		(1<<VNI_HASH_BITS)

#define GENEVE_BASE_HLEN (sizeof(struct udphdr) + sizeof(struct genevehdr))
#define GENEVE_IPV4_HLEN (ETH_HLEN + sizeof(struct iphdr) + GENEVE_BASE_HLEN)
#define GENEVE_IPV6_HLEN (ETH_HLEN + sizeof(struct ipv6hdr) + GENEVE_BASE_HLEN)

struct geneve_dev_node {
	struct hlist_node hlist;
	struct geneve_dev *geneve;
};

struct geneve_dev {
	struct geneve_dev_node hlist4;	/* vni hash table for IPv4 socket */
#if IS_ENABLED(CONFIG_IPV6)
	struct geneve_dev_node hlist6;	/* vni hash table for IPv6 socket */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct net	   *net;	/* netns for packet i/o */
	struct net_device  *dev;	/* netdev for geneve tunnel */
	struct ip_tunnel_info info;
	struct geneve_sock __rcu *sock4;	/* IPv4 socket used for geneve tunnel */
#if IS_ENABLED(CONFIG_IPV6)
	struct geneve_sock __rcu *sock6;	/* IPv6 socket used for geneve tunnel */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct list_head   next;	/* geneve's per namespace list */
	struct gro_cells   gro_cells;
	bool		   collect_md;
	bool		   use_udp6_rx_checksums;
	bool		   ttl_inherit;
	enum ifla_geneve_df df;
};

struct geneve_sock {
	bool			collect_md;
	struct list_head	list;
	struct socket		*sock;
	struct rcu_head		rcu;
	int			refcnt;
	struct hlist_head	vni_list[VNI_HASH_SIZE];
};

static int (*klpe_geneve_build_skb)(struct dst_entry *dst, struct sk_buff *skb,
			    const struct ip_tunnel_info *info,
			    bool xnet, int ip_hdr_len);

static struct rtable *klpp_geneve_get_v4_rt(struct sk_buff *skb,
				       struct net_device *dev,
				       struct geneve_sock *gs4,
				       struct flowi4 *fl4,
				       /*
					* Fix CVE-2020-25645
					*  -1 line, +2 lines
					*/
				       const struct ip_tunnel_info *info,
				       __be16 dport, __be16 sport)
{
	bool use_cache = ip_tunnel_dst_cache_usable(skb, info);
	struct geneve_dev *geneve = netdev_priv(dev);
	struct dst_cache *dst_cache;
	struct rtable *rt = NULL;
	__u8 tos;

	if (!gs4)
		return ERR_PTR(-EIO);

	memset(fl4, 0, sizeof(*fl4));
	fl4->flowi4_mark = skb->mark;
	fl4->flowi4_proto = IPPROTO_UDP;
	fl4->daddr = info->key.u.ipv4.dst;
	fl4->saddr = info->key.u.ipv4.src;
	/*
	 * Fix CVE-2020-25645
	 *  +2 lines
	 */
	fl4->fl4_dport = dport;
	fl4->fl4_sport = sport;

	tos = info->key.tos;
	if ((tos == 1) && !geneve->collect_md) {
		tos = ip_tunnel_get_dsfield(ip_hdr(skb), skb);
		use_cache = false;
	}
	fl4->flowi4_tos = RT_TOS(tos);

	dst_cache = (struct dst_cache *)&info->dst_cache;
	if (use_cache) {
		rt = dst_cache_get_ip4(dst_cache, &fl4->saddr);
		if (rt)
			return rt;
	}
	rt = ip_route_output_key(geneve->net, fl4);
	if (IS_ERR(rt)) {
		netdev_dbg(dev, "no route to %pI4\n", &fl4->daddr);
		return ERR_PTR(-ENETUNREACH);
	}
	if (rt->dst.dev == dev) { /* is this necessary? */
		netdev_dbg(dev, "circular route to %pI4\n", &fl4->daddr);
		ip_rt_put(rt);
		return ERR_PTR(-ELOOP);
	}
	if (use_cache)
		dst_cache_set_ip4(dst_cache, &rt->dst, fl4->saddr);
	return rt;
}

#if IS_ENABLED(CONFIG_IPV6)
static struct dst_entry *klpp_geneve_get_v6_dst(struct sk_buff *skb,
					   struct net_device *dev,
					   struct geneve_sock *gs6,
					   struct flowi6 *fl6,
					   /*
					    * Fix CVE-2020-25645
					    *  -1 line, +2 lines
					    */
					   const struct ip_tunnel_info *info,
					   __be16 dport, __be16 sport)
{
	bool use_cache = ip_tunnel_dst_cache_usable(skb, info);
	struct geneve_dev *geneve = netdev_priv(dev);
	struct dst_entry *dst = NULL;
	struct dst_cache *dst_cache;
	__u8 prio;

	if (!gs6)
		return ERR_PTR(-EIO);

	memset(fl6, 0, sizeof(*fl6));
	fl6->flowi6_mark = skb->mark;
	fl6->flowi6_proto = IPPROTO_UDP;
	fl6->daddr = info->key.u.ipv6.dst;
	fl6->saddr = info->key.u.ipv6.src;
	/*
	 * Fix CVE-2020-25645
	 *  +3 lines
	 */
	fl6->fl6_dport = dport;
	fl6->fl6_sport = sport;

	prio = info->key.tos;
	if ((prio == 1) && !geneve->collect_md) {
		prio = ip_tunnel_get_dsfield(ip_hdr(skb), skb);
		use_cache = false;
	}

	fl6->flowlabel = ip6_make_flowinfo(RT_TOS(prio),
					   info->key.label);
	dst_cache = (struct dst_cache *)&info->dst_cache;
	if (use_cache) {
		dst = dst_cache_get_ip6(dst_cache, &fl6->saddr);
		if (dst)
			return dst;
	}
	dst = ipv6_stub->ipv6_dst_lookup_flow(geneve->net, gs6->sock->sk, fl6,
					      NULL);
	if (IS_ERR(dst)) {
		netdev_dbg(dev, "no route to %pI6\n", &fl6->daddr);
		return ERR_PTR(-ENETUNREACH);
	}
	if (dst->dev == dev) { /* is this necessary? */
		netdev_dbg(dev, "circular route to %pI6\n", &fl6->daddr);
		dst_release(dst);
		return ERR_PTR(-ELOOP);
	}

	if (use_cache)
		dst_cache_set_ip6(dst_cache, dst, &fl6->saddr);
	return dst;
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static int klpp_geneve_xmit_skb(struct sk_buff *skb, struct net_device *dev,
			   struct geneve_dev *geneve,
			   const struct ip_tunnel_info *info)
{
	bool xnet = !net_eq(geneve->net, dev_net(geneve->dev));
	struct geneve_sock *gs4 = rcu_dereference(geneve->sock4);
	const struct ip_tunnel_key *key = &info->key;
	struct rtable *rt;
	struct flowi4 fl4;
	__u8 tos, ttl;
	__be16 df = 0;
	__be16 sport;
	int err;

	/*
	 * Fix CVE-2020-25645
	 *  -1 line, +3 lines
	 */
	sport = udp_flow_src_port(geneve->net, skb, 1, USHRT_MAX, true);
	rt = klpp_geneve_get_v4_rt(skb, dev, gs4, &fl4, info,
				   geneve->info.key.tp_dst, sport);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	skb_tunnel_check_pmtu(skb, &rt->dst,
			      GENEVE_IPV4_HLEN + info->options_len);

	/*
	 * Fix CVE-2020-25645
	 *  -1 line
	 */
	if (geneve->collect_md) {
		tos = ip_tunnel_ecn_encap(key->tos, ip_hdr(skb), skb);
		ttl = key->ttl;

		df = key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;
	} else {
		tos = ip_tunnel_ecn_encap(fl4.flowi4_tos, ip_hdr(skb), skb);
		if (geneve->ttl_inherit)
			ttl = ip_tunnel_get_ttl(ip_hdr(skb), skb);
		else
			ttl = key->ttl;
		ttl = ttl ? : ip4_dst_hoplimit(&rt->dst);

		if (geneve->df == GENEVE_DF_SET) {
			df = htons(IP_DF);
		} else if (geneve->df == GENEVE_DF_INHERIT) {
			struct ethhdr *eth = eth_hdr(skb);

			if (ntohs(eth->h_proto) == ETH_P_IPV6) {
				df = htons(IP_DF);
			} else if (ntohs(eth->h_proto) == ETH_P_IP) {
				struct iphdr *iph = ip_hdr(skb);

				if (iph->frag_off & htons(IP_DF))
					df = htons(IP_DF);
			}
		}
	}

	err = (*klpe_geneve_build_skb)(&rt->dst, skb, info, xnet, sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	(*klpe_udp_tunnel_xmit_skb)(rt, gs4->sock->sk, skb, fl4.saddr, fl4.daddr,
			    tos, ttl, df, sport, geneve->info.key.tp_dst,
			    !net_eq(geneve->net, dev_net(geneve->dev)),
			    !(info->key.tun_flags & TUNNEL_CSUM));
	return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
static int klpp_geneve6_xmit_skb(struct sk_buff *skb, struct net_device *dev,
			    struct geneve_dev *geneve,
			    const struct ip_tunnel_info *info)
{
	bool xnet = !net_eq(geneve->net, dev_net(geneve->dev));
	struct geneve_sock *gs6 = rcu_dereference(geneve->sock6);
	const struct ip_tunnel_key *key = &info->key;
	struct dst_entry *dst = NULL;
	struct flowi6 fl6;
	__u8 prio, ttl;
	__be16 sport;
	int err;

	/*
	 * Fix CVE-2020-25645
	 *  -1 line, +3 lines
	 */
	sport = udp_flow_src_port(geneve->net, skb, 1, USHRT_MAX, true);
	dst = klpp_geneve_get_v6_dst(skb, dev, gs6, &fl6, info,
				     geneve->info.key.tp_dst, sport);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	skb_tunnel_check_pmtu(skb, dst, GENEVE_IPV6_HLEN + info->options_len);

	/*
	 * Fix CVE-2020-25645
	 *  -1 line
	 */
	if (geneve->collect_md) {
		prio = ip_tunnel_ecn_encap(key->tos, ip_hdr(skb), skb);
		ttl = key->ttl;
	} else {
		prio = ip_tunnel_ecn_encap(ip6_tclass(fl6.flowlabel),
					   ip_hdr(skb), skb);
		if (geneve->ttl_inherit)
			ttl = ip_tunnel_get_ttl(ip_hdr(skb), skb);
		else
			ttl = key->ttl;
		ttl = ttl ? : ip6_dst_hoplimit(dst);
	}
	err = (*klpe_geneve_build_skb)(dst, skb, info, xnet, sizeof(struct ipv6hdr));
	if (unlikely(err))
		return err;

	(*klpe_udp_tunnel6_xmit_skb)(dst, gs6->sock->sk, skb, dev,
			     &fl6.saddr, &fl6.daddr, prio, ttl,
			     info->key.label, sport, geneve->info.key.tp_dst,
			     !(info->key.tun_flags & TUNNEL_CSUM));
	return 0;
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

netdev_tx_t klpp_geneve_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct geneve_dev *geneve = netdev_priv(dev);
	struct ip_tunnel_info *info = NULL;
	int err;

	if (geneve->collect_md) {
		info = skb_tunnel_info(skb);
		if (unlikely(!info || !(info->mode & IP_TUNNEL_INFO_TX))) {
			err = -EINVAL;
			netdev_dbg(dev, "no tunnel metadata\n");
			goto tx_error;
		}
	} else {
		info = &geneve->info;
	}

	rcu_read_lock();
#if IS_ENABLED(CONFIG_IPV6)
	if (info->mode & IP_TUNNEL_INFO_IPV6)
		err = klpp_geneve6_xmit_skb(skb, dev, geneve, info);
	else
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		err = klpp_geneve_xmit_skb(skb, dev, geneve, info);
	rcu_read_unlock();

	if (likely(!err))
		return NETDEV_TX_OK;
tx_error:
	dev_kfree_skb(skb);

	if (err == -ELOOP)
		dev->stats.collisions++;
	else if (err == -ENETUNREACH)
		dev->stats.tx_carrier_errors++;

	dev->stats.tx_errors++;
	return NETDEV_TX_OK;
}

int klpp_geneve_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
	struct ip_tunnel_info *info = skb_tunnel_info(skb);
	struct geneve_dev *geneve = netdev_priv(dev);
	/*
	 * Fix CVE-2020-25645
	 *  +1 line
	 */
	__be16 sport;

	if (ip_tunnel_info_af(info) == AF_INET) {
		struct rtable *rt;
		struct flowi4 fl4;
		struct geneve_sock *gs4 = rcu_dereference(geneve->sock4);

		/*
		 * Fix CVE-2020-25645
		 *  -1 line, +4 lines
		 */
		sport = udp_flow_src_port(geneve->net, skb,
					  1, USHRT_MAX, true);
		rt = klpp_geneve_get_v4_rt(skb, dev, gs4, &fl4, info,
					   geneve->info.key.tp_dst, sport);
		if (IS_ERR(rt))
			return PTR_ERR(rt);

		ip_rt_put(rt);
		info->key.u.ipv4.src = fl4.saddr;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (ip_tunnel_info_af(info) == AF_INET6) {
		struct dst_entry *dst;
		struct flowi6 fl6;
		struct geneve_sock *gs6 = rcu_dereference(geneve->sock6);

		/*
		 * Fix CVE-2020-25645
		 *  -1 line, +4 lines
		 */
		sport = udp_flow_src_port(geneve->net, skb,
					  1, USHRT_MAX, true);
		dst = klpp_geneve_get_v6_dst(skb, dev, gs6, &fl6, info,
					     geneve->info.key.tp_dst, sport);
		if (IS_ERR(dst))
			return PTR_ERR(dst);

		dst_release(dst);
		info->key.u.ipv6.src = fl6.saddr;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	} else {
		return -EINVAL;
	}

	/*
	 * Fix CVE-2020-25645
	 *  -2 lines, +1 line
	 */
	info->key.tp_src = sport;
	info->key.tp_dst = geneve->info.key.tp_dst;
	return 0;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "udp_tunnel6_xmit_skb", (void *)&klpe_udp_tunnel6_xmit_skb,
	  "ip6_udp_tunnel" },
	{ "udp_tunnel_xmit_skb", (void *)&klpe_udp_tunnel_xmit_skb,
	  "udp_tunnel" },
	{ "geneve_build_skb", (void *)&klpe_geneve_build_skb, "geneve" },
};

static int livepatch_bsc1177513_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1177513_module_nb = {
	.notifier_call = livepatch_bsc1177513_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1177513_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1177513_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1177513_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1177513_module_nb);
}
