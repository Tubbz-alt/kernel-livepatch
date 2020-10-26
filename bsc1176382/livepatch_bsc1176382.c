/*
 * livepatch_bsc1176382
 *
 * Fix for CVE-2020-25212, bsc#1176382
 *
 *  Upstream commits:
 *  b4487b935452 ("nfs: Fix getxattr kernel panic and memory overflow")
 *  d33030e2ee35 ("nfs: Fix security label length not being reset")
 *
 *  SLE12-SP2 and -SP3 commits:
 *  949d021bcd20975df3afdc4361afb64103028616
 *  317e0248becfb39dfeb08284c0bb365410362c64
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  41de7ea85d3afe9018264e0984b0024f797b3682
 *  a53755ab55891c1efac767fa37609a0bbdabfd8e
 *
 *  SLE15-SP2 commits:
 *  0de797a69f9b6f01e4f2df7de1f63dbc7f8021e6
 *  c73c6391aa46047deeac5ced6c0bfd9ee0f49ca4
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
#include "livepatch_bsc1176382.h"

int livepatch_bsc1176382_init(void)
{
	int r;

	r = livepatch_bsc1176382_nfs4xdr_init();
	if (r)
		return r;

	r = livepatch_bsc1176382_dir_init();
	if (r) {
		livepatch_bsc1176382_nfs4xdr_cleanup();
		return r;
	}

	return 0;
}

void livepatch_bsc1176382_cleanup(void)
{
	livepatch_bsc1176382_dir_cleanup();
	livepatch_bsc1176382_nfs4xdr_cleanup();
}
