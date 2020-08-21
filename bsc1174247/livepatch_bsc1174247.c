/*
 * livepatch_bsc1174247
 *
 * Fix for CVE-2020-14331, bsc#1174247
 *
 *  Upstream commit:
 *  None yet.
 *
 *  SLE12-SP2 and -SP3 commit:
 *  2d2d4f9275c23f7ecfcd91a6310cebd22b19e6c4
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  8991ff62cacb705e10bad9b20c2bf3cda423fb6b
 *  7ae4119811a01d10a66374820660afe768daffa0
 *
 *  SLE15-SP2 commits:
 *  ffe1c3ffe9a5c6263108f23025080037a9abfc96
 *  2b80031f91a642b949e22bc2d64b607819ccc36b
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

#if IS_ENABLED(CONFIG_VGA_CONSOLE)

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1174247.h"
#include "../kallsyms_relocs.h"

/* klp-ccp: from drivers/video/console/vgacon.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/console.h>
#include <linux/string.h>
#include <linux/kd.h>
#include <linux/slab.h>
#include <linux/vt_kern.h>
#include <linux/sched.h>
#include <linux/selection.h>
#include <linux/spinlock.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/screen_info.h>
#include <asm/io.h>

static raw_spinlock_t (*klpe_vga_lock);

static unsigned long	(*klpe_vga_vram_base)		__read_mostly;
static unsigned long	(*klpe_vga_vram_end)		__read_mostly;

static u16		(*klpe_vga_video_port_reg)	__read_mostly;

static bool 		(*klpe_vga_is_gfx);

/*
 * Livepatch note:
 * For CONFIG_VGACON_SOFT_SCROLLBACK this gets only written to and
 * externalization is not required (and not even possible as
 * this symbol has been away in the target kernel).
 */
static unsigned int 	vga_rolled_over;

static bool (*klpe_vga_hardscroll_enabled);

static inline void klpr_write_vga(unsigned char reg, unsigned int val)
{
	unsigned int v1, v2;
	unsigned long flags;

	/*
	 * ddprintk might set the console position from interrupt
	 * handlers, thus the write has to be IRQ-atomic.
	 */
	raw_spin_lock_irqsave(&(*klpe_vga_lock), flags);
	v1 = reg + (val & 0xff00);
	v2 = reg + 1 + ((val << 8) & 0xff00);
	outw(v1, (*klpe_vga_video_port_reg));
	outw(v2, (*klpe_vga_video_port_reg));
	raw_spin_unlock_irqrestore(&(*klpe_vga_lock), flags);
}

static inline void klpr_vga_set_mem_top(struct vc_data *c)
{
	klpr_write_vga(12, (c->vc_visible_origin - (*klpe_vga_vram_base)) / 2);
}

#ifdef CONFIG_VGACON_SOFT_SCROLLBACK

struct vgacon_scrollback_info {
	void *data;
	int tail;
	int size;
	int rows;
	int cnt;
	int cur;
	int save;
	int restore;
};

static struct vgacon_scrollback_info *(*klpe_vgacon_scrollback_cur);

static void klpp_vgacon_scrollback_update(struct vc_data *c, int t, int count)
{
	void *p;

	if (!(*klpe_vgacon_scrollback_cur)->data || !(*klpe_vgacon_scrollback_cur)->size ||
	    c->vc_num != fg_console)
		return;

	p = (void *) (c->vc_origin + t * c->vc_size_row);

	while (count--) {
		/*
		 * Fix CVE-2020-14331
		 *  +4 lines
		 */
		if (((*klpe_vgacon_scrollback_cur)->tail + c->vc_size_row) >
		    (*klpe_vgacon_scrollback_cur)->size)
			(*klpe_vgacon_scrollback_cur)->tail = 0;

		scr_memcpyw((*klpe_vgacon_scrollback_cur)->data +
			    (*klpe_vgacon_scrollback_cur)->tail,
			    p, c->vc_size_row);

		(*klpe_vgacon_scrollback_cur)->cnt++;
		p += c->vc_size_row;
		(*klpe_vgacon_scrollback_cur)->tail += c->vc_size_row;

		if ((*klpe_vgacon_scrollback_cur)->tail >= (*klpe_vgacon_scrollback_cur)->size)
			(*klpe_vgacon_scrollback_cur)->tail = 0;

		if ((*klpe_vgacon_scrollback_cur)->cnt > (*klpe_vgacon_scrollback_cur)->rows)
			(*klpe_vgacon_scrollback_cur)->cnt = (*klpe_vgacon_scrollback_cur)->rows;

		(*klpe_vgacon_scrollback_cur)->cur = (*klpe_vgacon_scrollback_cur)->cnt;
	}
}

static void (*klpe_vgacon_restore_screen)(struct vc_data *c);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_VGACON_SOFT_SCROLLBACK */

bool klpp_vgacon_scroll(struct vc_data *c, unsigned int t, unsigned int b,
		enum con_scroll dir, unsigned int lines)
{
	unsigned long oldo;
	unsigned int delta;

	if (t || b != c->vc_rows || (*klpe_vga_is_gfx) || c->vc_mode != KD_TEXT)
		return false;

	if (!(*klpe_vga_hardscroll_enabled) || lines >= c->vc_rows / 2)
		return false;

	(*klpe_vgacon_restore_screen)(c);
	oldo = c->vc_origin;
	delta = lines * c->vc_size_row;
	if (dir == SM_UP) {
		klpp_vgacon_scrollback_update(c, t, lines);
		if (c->vc_scr_end + delta >= (*klpe_vga_vram_end)) {
			scr_memcpyw((u16 *) (*klpe_vga_vram_base),
				    (u16 *) (oldo + delta),
				    c->vc_screenbuf_size - delta);
			c->vc_origin = (*klpe_vga_vram_base);
			vga_rolled_over = oldo - (*klpe_vga_vram_base);
		} else
			c->vc_origin += delta;
		scr_memsetw((u16 *) (c->vc_origin + c->vc_screenbuf_size -
				     delta), c->vc_video_erase_char,
			    delta);
	} else {
		if (oldo - delta < (*klpe_vga_vram_base)) {
			scr_memmovew((u16 *) ((*klpe_vga_vram_end) -
					      c->vc_screenbuf_size +
					      delta), (u16 *) oldo,
				     c->vc_screenbuf_size - delta);
			c->vc_origin = (*klpe_vga_vram_end) - c->vc_screenbuf_size;
			vga_rolled_over = 0;
		} else
			c->vc_origin -= delta;
		c->vc_scr_end = c->vc_origin + c->vc_screenbuf_size;
		scr_memsetw((u16 *) (c->vc_origin), c->vc_video_erase_char,
			    delta);
	}
	c->vc_scr_end = c->vc_origin + c->vc_screenbuf_size;
	c->vc_visible_origin = c->vc_origin;
	klpr_vga_set_mem_top(c);
	c->vc_pos = (c->vc_pos - oldo) + c->vc_origin;
	return true;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "vga_lock", (void *)&klpe_vga_lock },
	{ "vga_vram_base", (void *)&klpe_vga_vram_base },
	{ "vga_vram_end", (void *)&klpe_vga_vram_end },
	{ "vga_video_port_reg", (void *)&klpe_vga_video_port_reg },
	{ "vga_is_gfx", (void *)&klpe_vga_is_gfx },
	{ "vga_hardscroll_enabled", (void *)&klpe_vga_hardscroll_enabled },
	{ "vgacon_scrollback_cur", (void *)&klpe_vgacon_scrollback_cur },
	{ "vgacon_restore_screen", (void *)&klpe_vgacon_restore_screen },
};

int livepatch_bsc1174247_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_VGA_CONSOLE) */
