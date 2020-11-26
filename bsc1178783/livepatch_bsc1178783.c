/*
 * livepatch_bsc1178783
 *
 * Fix for CVE-2020-25705, bsc#1178783
 *
 *  Upstream commit:
 *  b38e7819cae9 ("icmp: randomize the global rate limiter")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  fad13a8ced9debc0545922139dbd9c21da36c170
 *
 *  SLE12-SP4 and SLE15 commit:
 *  5acc8a67e49d6d6424ddb47df9ca1c578fb5082c
 *
 *  SLE12-SP5 and SLE15-SP1 commits:
 *  41c75102e9607ecb079d8b18a4dad0501d9bd4b9
 *  5acc8a67e49d6d6424ddb47df9ca1c578fb5082c
 *
 *  SLE15-SP2 commit:
 *  3f6a76f3daa398e5475b0054e90140f228e89149
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

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1178783.h"
#include "../kallsyms_relocs.h"

/* klp-ccp: from net/ipv4/icmp.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <net/snmp.h>

/* klp-ccp: from include/net/ip.h */
static int (*klpe_sysctl_icmp_msgs_per_sec);
static int (*klpe_sysctl_icmp_msgs_burst);

/* klp-ccp: from net/ipv4/icmp.c */
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <net/checksum.h>
#include <net/ip_fib.h>
#include <net/l3mdev.h>

static struct {
	spinlock_t	lock;
	u32		credit;
	u32		stamp;
} (*klpe_icmp_global);

bool klpp_icmp_global_allow(void)
{
	u32 credit, delta, incr = 0, now = (u32)jiffies;
	bool rc = false;

	/* Check if token bucket is empty and cannot be refilled
	 * without taking the spinlock. The READ_ONCE() are paired
	 * with the following WRITE_ONCE() in this same function.
	 */
	if (!READ_ONCE((*klpe_icmp_global).credit)) {
		delta = min_t(u32, now - READ_ONCE((*klpe_icmp_global).stamp), HZ);
		if (delta < HZ / 50)
			return false;
	}

	spin_lock(&(*klpe_icmp_global).lock);
	delta = min_t(u32, now - (*klpe_icmp_global).stamp, HZ);
	if (delta >= HZ / 50) {
		incr = (*klpe_sysctl_icmp_msgs_per_sec) * delta / HZ ;
		if (incr)
			WRITE_ONCE((*klpe_icmp_global).stamp, now);
	}
	credit = min_t(u32, (*klpe_icmp_global).credit + incr, (*klpe_sysctl_icmp_msgs_burst));
	if (credit) {
		/*
		 * Fix CVE-2020-25705
		 *  -1 line, +4 lines
		 */
		/* We want to use a credit of one in average, but need to randomize
		 * it for security reasons.
		 */
		credit = max_t(int, credit - prandom_u32_max(3), 0);
		rc = true;
	}
	WRITE_ONCE((*klpe_icmp_global).credit, credit);
	spin_unlock(&(*klpe_icmp_global).lock);
	return rc;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sysctl_icmp_msgs_per_sec", (void *)&klpe_sysctl_icmp_msgs_per_sec },
	{ "sysctl_icmp_msgs_burst", (void *)&klpe_sysctl_icmp_msgs_burst },
	{ "icmp_global", (void *)&klpe_icmp_global },
};

int livepatch_bsc1178783_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
