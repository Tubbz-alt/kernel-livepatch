/*
 * livepatch_bsc1178622
 *
 * Fix for CVE-2020-25668, bsc#1178622
 *
 *  Upstream commit:
 *  90bfdeef83f1 ("tty: make FONTX ioctl use the tty pointer they were actually
 *                 passed")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  38414479f9fdbbb9991316c22d55d14501372f79
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  2fb3bcf2e9b23fecd5285e7eb4fba0c93925dcc1
 *
 *  SLE15-SP2 commit:
 *  fda631fb8397cf24567c7c333294d5f35691651c
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

#if IS_ENABLED(CONFIG_VT)

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1178622.h"
#include "../kallsyms_relocs.h"

/* klp-ccp: from drivers/tty/vt/vt_ioctl.c */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/sched/signal.h>
#include <linux/tty.h>

/* klp-ccp: from include/linux/tty.h */
int klpp_vt_ioctl(struct tty_struct *tty,
		    unsigned int cmd, unsigned long arg);

long klpp_vt_compat_ioctl(struct tty_struct *tty,
		     unsigned int cmd, unsigned long arg);

/* klp-ccp: from drivers/tty/vt/vt_ioctl.c */
#include <linux/timer.h>
#include <linux/kernel.h>
#include <linux/compat.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/major.h>
#include <linux/fs.h>
#include <linux/console.h>
#include <linux/timex.h>
#include <asm/io.h>
#include <linux/uaccess.h>
#include <linux/nospec.h>

/* klp-ccp: from include/linux/kbd_kern.h */
static int (*klpe_set_console)(int nr);

/* klp-ccp: from drivers/tty/vt/vt_ioctl.c */
#include <linux/vt_kern.h>

/* klp-ccp: from include/linux/vt_kern.h */
static int (*klpe_kbd_rate)(struct kbd_repeat *rep);

static int (*klpe_vc_allocate)(unsigned int console);
static int (*klpe_vc_cons_allocated)(unsigned int console);

static struct vc_data *(*klpe_vc_deallocate)(unsigned int console);

static int (*klpe_con_font_op)(struct vc_data *vc, struct console_font_op *op);
static int (*klpe_con_set_cmap)(unsigned char __user *cmap);
static int (*klpe_con_get_cmap)(unsigned char __user *cmap);

static int (*klpe_tioclinux)(struct tty_struct *tty, unsigned long arg);

#ifdef CONFIG_CONSOLE_TRANSLATIONS

static int (*klpe_con_set_trans_old)(unsigned char __user * table);
static int (*klpe_con_get_trans_old)(unsigned char __user * table);
static int (*klpe_con_set_trans_new)(unsigned short __user * table);
static int (*klpe_con_get_trans_new)(unsigned short __user * table);
static int (*klpe_con_clear_unimap)(struct vc_data *vc);
static int (*klpe_con_set_unimap)(struct vc_data *vc, ushort ct, struct unipair __user *list);
static int (*klpe_con_get_unimap)(struct vc_data *vc, ushort ct, ushort __user *uct, struct unipair __user *list);

#else
#error "klp-ccp: non-taken branch"
#endif

static int (*klpe_vt_waitactive)(int n);

static char (*klpe_vt_dont_switch);

static struct vt_spawn_console (*klpe_vt_spawn_con);

static int (*klpe_vt_do_diacrit)(unsigned int cmd, void __user *up, int eperm);
static int (*klpe_vt_do_kdskbmode)(int console, unsigned int arg);
static int (*klpe_vt_do_kdskbmeta)(int console, unsigned int arg);
static int (*klpe_vt_do_kbkeycode_ioctl)(int cmd, struct kbkeycode __user *user_kbkc,
								int perm);
static int (*klpe_vt_do_kdsk_ioctl)(int cmd, struct kbentry __user *user_kbe,
					int perm, int console);
static int (*klpe_vt_do_kdgkb_ioctl)(int cmd, struct kbsentry __user *user_kdgkb,
                                        int perm);
static int (*klpe_vt_do_kdskled)(int console, int cmd, unsigned long arg, int perm);
static int (*klpe_vt_do_kdgkbmode)(int console);
static int (*klpe_vt_do_kdgkbmeta)(int console);

/* klp-ccp: from include/linux/selection.h */
static struct vc_data *(*klpe_sel_cons);

/* klp-ccp: from drivers/tty/vt/vt_ioctl.c */
static struct tty_driver *(*klpe_console_driver);

#ifdef CONFIG_X86

/* klp-ccp: from arch/x86/include/asm/syscalls.h */
static long (*klpe_ksys_ioperm)(unsigned long from, unsigned long num, int turn_on);

#endif

static void (*klpe_complete_change_console)(struct vc_data *vc);

struct vt_event_wait {
	struct list_head list;
	struct vt_event event;
	int done;
};

static struct list_head (*klpe_vt_events);
static spinlock_t (*klpe_vt_event_lock);
static struct wait_queue_head (*klpe_vt_event_waitqueue);

static void klpr___vt_event_queue(struct vt_event_wait *vw)
{
	unsigned long flags;
	/* Prepare the event */
	INIT_LIST_HEAD(&vw->list);
	vw->done = 0;
	/* Queue our event */
	spin_lock_irqsave(&(*klpe_vt_event_lock), flags);
	list_add(&vw->list, &(*klpe_vt_events));
	spin_unlock_irqrestore(&(*klpe_vt_event_lock), flags);
}

static void klpr___vt_event_wait(struct vt_event_wait *vw)
{
	/* Wait for it to pass */
	wait_event_interruptible((*klpe_vt_event_waitqueue), vw->done);
}

static void klpr___vt_event_dequeue(struct vt_event_wait *vw)
{
	unsigned long flags;

	/* Dequeue it */
	spin_lock_irqsave(&(*klpe_vt_event_lock), flags);
	list_del(&vw->list);
	spin_unlock_irqrestore(&(*klpe_vt_event_lock), flags);
}

/**
 *	vt_event_wait		-	wait for an event
 *	@vw: our event
 *
 *	Waits for an event to occur which completes our vt_event_wait
 *	structure. On return the structure has wv->done set to 1 for success
 *	or 0 if some event such as a signal ended the wait.
 */

static void klpr_vt_event_wait(struct vt_event_wait *vw)
{
	klpr___vt_event_queue(vw);
	klpr___vt_event_wait(vw);
	klpr___vt_event_dequeue(vw);
}

/**
 *	vt_event_wait_ioctl	-	event ioctl handler
 *	@arg: argument to ioctl
 *
 *	Implement the VT_WAITEVENT ioctl using the VT event interface
 */

static int klpr_vt_event_wait_ioctl(struct vt_event __user *event)
{
	struct vt_event_wait vw;

	if (copy_from_user(&vw.event, event, sizeof(struct vt_event)))
		return -EFAULT;
	/* Highest supported event for now */
	if (vw.event.event & ~VT_MAX_EVENT)
		return -EINVAL;

	klpr_vt_event_wait(&vw);
	/* If it occurred report it */
	if (vw.done) {
		if (copy_to_user(event, &vw.event, sizeof(struct vt_event)))
			return -EFAULT;
		return 0;
	}
	return -EINTR;
}

#define GPFIRST 0x3b4
#define GPLAST 0x3df
#define GPNUM (GPLAST - GPFIRST + 1)

static inline int
/*
 * Fix CVE-2020-25668
 *  -1 line, +1 line
 */
klpp_do_fontx_ioctl(struct vc_data *vc, int cmd, struct consolefontdesc __user *user_cfd, int perm, struct console_font_op *op)
{
	struct consolefontdesc cfdarg;
	int i;

	if (copy_from_user(&cfdarg, user_cfd, sizeof(struct consolefontdesc))) 
		return -EFAULT;
 	
	switch (cmd) {
	case PIO_FONTX:
		if (!perm)
			return -EPERM;
		op->op = KD_FONT_OP_SET;
		op->flags = KD_FONT_FLAG_OLD;
		op->width = 8;
		op->height = cfdarg.charheight;
		op->charcount = cfdarg.charcount;
		op->data = cfdarg.chardata;
		/*
		 * Fix CVE-2020-25668
		 *  -1 line, +1 line
		 */
		return (*klpe_con_font_op)(vc, op);
	case GIO_FONTX: {
		op->op = KD_FONT_OP_GET;
		op->flags = KD_FONT_FLAG_OLD;
		op->width = 8;
		op->height = cfdarg.charheight;
		op->charcount = cfdarg.charcount;
		op->data = cfdarg.chardata;
		/*
		 * Fix CVE-2020-25668
		 *  -1 line, +1 line
		 */
		i = (*klpe_con_font_op)(vc, op);
		if (i)
			return i;
		cfdarg.charheight = op->height;
		cfdarg.charcount = op->charcount;
		if (copy_to_user(user_cfd, &cfdarg, sizeof(struct consolefontdesc)))
			return -EFAULT;
		return 0;
		}
	}
	return -EINVAL;
}

static inline int 
klpr_do_unimap_ioctl(int cmd, struct unimapdesc __user *user_ud, int perm, struct vc_data *vc)
{
	struct unimapdesc tmp;

	if (copy_from_user(&tmp, user_ud, sizeof tmp))
		return -EFAULT;
	switch (cmd) {
	case PIO_UNIMAP:
		if (!perm)
			return -EPERM;
		return (*klpe_con_set_unimap)(vc, tmp.entry_ct, tmp.entries);
	case GIO_UNIMAP:
		if (!perm && fg_console != vc->vc_num)
			return -EPERM;
		return (*klpe_con_get_unimap)(vc, tmp.entry_ct, &(user_ud->entry_ct), tmp.entries);
	}
	return 0;
}

static int klpr_vt_disallocate(unsigned int vc_num)
{
	struct vc_data *vc = NULL;
	int ret = 0;

	console_lock();
	if ((((*klpe_console_driver)->ttys[vc_num] && (*klpe_console_driver)->ttys[vc_num]->count) || vc_num == fg_console || vc_cons[vc_num].d == (*klpe_sel_cons)))
		ret = -EBUSY;
	else if (vc_num)
		vc = (*klpe_vc_deallocate)(vc_num);
	console_unlock();

	if (vc && vc_num >= MIN_NR_CONSOLES) {
		tty_port_destroy(&vc->port);
		kfree(vc);
	}

	return ret;
}

static void (*klpe_vt_disallocate_all)(void);

int klpp_vt_ioctl(struct tty_struct *tty,
	     unsigned int cmd, unsigned long arg)
{
	struct vc_data *vc = tty->driver_data;
	struct console_font_op op;	/* used in multiple places here */
	unsigned int console;
	unsigned char ucval;
	unsigned int uival;
	void __user *up = (void __user *)arg;
	int i, perm;
	int ret = 0;

	console = vc->vc_num;


	if (!(*klpe_vc_cons_allocated)(console)) { 	/* impossible? */
		ret = -ENOIOCTLCMD;
		goto out;
	}


	/*
	 * To have permissions to do most of the vt ioctls, we either have
	 * to be the owner of the tty, or have CAP_SYS_TTY_CONFIG.
	 */
	perm = 0;
	if (current->signal->tty == tty || capable(CAP_SYS_TTY_CONFIG))
		perm = 1;
 
	switch (cmd) {
	case TIOCLINUX:
		ret = (*klpe_tioclinux)(tty, arg);
		break;
	case KIOCSOUND:
		if (!perm)
			return -EPERM;
		/*
		 * The use of PIT_TICK_RATE is historic, it used to be
		 * the platform-dependent CLOCK_TICK_RATE between 2.6.12
		 * and 2.6.36, which was a minor but unfortunate ABI
		 * change. kd_mksound is locked by the input layer.
		 */
		if (arg)
			arg = PIT_TICK_RATE / arg;
		kd_mksound(arg, 0);
		break;

	case KDMKTONE:
		if (!perm)
			return -EPERM;
	{
		unsigned int ticks, count;
		
		/*
		 * Generate the tone for the appropriate number of ticks.
		 * If the time is zero, turn off sound ourselves.
		 */
		ticks = msecs_to_jiffies((arg >> 16) & 0xffff);
		count = ticks ? (arg & 0xffff) : 0;
		if (count)
			count = PIT_TICK_RATE / count;
		kd_mksound(count, ticks);
		break;
	}

	case KDGKBTYPE:
		/*
		 * this is naïve.
		 */
		ucval = KB_101;
		ret = put_user(ucval, (char __user *)arg);
		break;

#ifdef CONFIG_X86
	case KDADDIO:
	case KDDELIO:
		/*
		 * KDADDIO and KDDELIO may be able to add ports beyond what
		 * we reject here, but to be safe...
		 *
		 * These are locked internally via sys_ioperm
		 */
		if (arg < GPFIRST || arg > GPLAST) {
			ret = -EINVAL;
			break;
		}
		ret = (*klpe_ksys_ioperm)(arg, 1, (cmd == KDADDIO)) ? -ENXIO : 0;
		break;

	case KDENABIO:
	case KDDISABIO:
		ret = (*klpe_ksys_ioperm)(GPFIRST, GPNUM,
				  (cmd == KDENABIO)) ? -ENXIO : 0;
		break;
#endif
	case KDKBDREP:
	{
		struct kbd_repeat kbrep;
		
		if (!capable(CAP_SYS_TTY_CONFIG))
			return -EPERM;

		if (copy_from_user(&kbrep, up, sizeof(struct kbd_repeat))) {
			ret =  -EFAULT;
			break;
		}
		ret = (*klpe_kbd_rate)(&kbrep);
		if (ret)
			break;
		if (copy_to_user(up, &kbrep, sizeof(struct kbd_repeat)))
			ret = -EFAULT;
		break;
	}

	case KDSETMODE:
		/*
		 * currently, setting the mode from KD_TEXT to KD_GRAPHICS
		 * doesn't do a whole lot. i'm not sure if it should do any
		 * restoration of modes or what...
		 *
		 * XXX It should at least call into the driver, fbdev's definitely
		 * need to restore their engine state. --BenH
		 */
		if (!perm)
			return -EPERM;
		switch (arg) {
		case KD_GRAPHICS:
			break;
		case KD_TEXT0:
		case KD_TEXT1:
			arg = KD_TEXT;
		case KD_TEXT:
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		/* FIXME: this needs the console lock extending */
		if (vc->vc_mode == (unsigned char) arg)
			break;
		vc->vc_mode = (unsigned char) arg;
		if (console != fg_console)
			break;
		/*
		 * explicitly blank/unblank the screen if switching modes
		 */
		console_lock();
		if (arg == KD_TEXT)
			do_unblank_screen(1);
		else
			do_blank_screen(1);
		console_unlock();
		break;

	case KDGETMODE:
		uival = vc->vc_mode;
		goto setint;

	case KDMAPDISP:
	case KDUNMAPDISP:
		/*
		 * these work like a combination of mmap and KDENABIO.
		 * this could be easily finished.
		 */
		ret = -EINVAL;
		break;

	case KDSKBMODE:
		if (!perm)
			return -EPERM;
		ret = (*klpe_vt_do_kdskbmode)(console, arg);
		if (ret == 0)
			tty_ldisc_flush(tty);
		break;

	case KDGKBMODE:
		uival = (*klpe_vt_do_kdgkbmode)(console);
		ret = put_user(uival, (int __user *)arg);
		break;

	/* this could be folded into KDSKBMODE, but for compatibility
	   reasons it is not so easy to fold KDGKBMETA into KDGKBMODE */
	case KDSKBMETA:
		ret = (*klpe_vt_do_kdskbmeta)(console, arg);
		break;

	case KDGKBMETA:
		/* FIXME: should review whether this is worth locking */
		uival = (*klpe_vt_do_kdgkbmeta)(console);
	setint:
		ret = put_user(uival, (int __user *)arg);
		break;

	case KDGETKEYCODE:
	case KDSETKEYCODE:
		if(!capable(CAP_SYS_TTY_CONFIG))
			perm = 0;
		ret = (*klpe_vt_do_kbkeycode_ioctl)(cmd, up, perm);
		break;

	case KDGKBENT:
	case KDSKBENT:
		ret = (*klpe_vt_do_kdsk_ioctl)(cmd, up, perm, console);
		break;

	case KDGKBSENT:
	case KDSKBSENT:
		ret = (*klpe_vt_do_kdgkb_ioctl)(cmd, up, perm);
		break;

	/* Diacritical processing. Handled in keyboard.c as it has
	   to operate on the keyboard locks and structures */
	case KDGKBDIACR:
	case KDGKBDIACRUC:
	case KDSKBDIACR:
	case KDSKBDIACRUC:
		ret = (*klpe_vt_do_diacrit)(cmd, up, perm);
		break;

	/* the ioctls below read/set the flags usually shown in the leds */
	/* don't use them - they will go away without warning */
	case KDGKBLED:
	case KDSKBLED:
	case KDGETLED:
	case KDSETLED:
		ret = (*klpe_vt_do_kdskled)(console, cmd, arg, perm);
		break;

	/*
	 * A process can indicate its willingness to accept signals
	 * generated by pressing an appropriate key combination.
	 * Thus, one can have a daemon that e.g. spawns a new console
	 * upon a keypress and then changes to it.
	 * See also the kbrequest field of inittab(5).
	 */
	case KDSIGACCEPT:
	{
		if (!perm || !capable(CAP_KILL))
			return -EPERM;
		if (!valid_signal(arg) || arg < 1 || arg == SIGKILL)
			ret = -EINVAL;
		else {
			spin_lock_irq(&(*klpe_vt_spawn_con).lock);
			put_pid((*klpe_vt_spawn_con).pid);
			(*klpe_vt_spawn_con).pid = get_pid(task_pid(current));
			(*klpe_vt_spawn_con).sig = arg;
			spin_unlock_irq(&(*klpe_vt_spawn_con).lock);
		}
		break;
	}

	case VT_SETMODE:
	{
		struct vt_mode tmp;

		if (!perm)
			return -EPERM;
		if (copy_from_user(&tmp, up, sizeof(struct vt_mode))) {
			ret = -EFAULT;
			goto out;
		}
		if (tmp.mode != VT_AUTO && tmp.mode != VT_PROCESS) {
			ret = -EINVAL;
			goto out;
		}
		console_lock();
		vc->vt_mode = tmp;
		/* the frsig is ignored, so we set it to 0 */
		vc->vt_mode.frsig = 0;
		put_pid(vc->vt_pid);
		vc->vt_pid = get_pid(task_pid(current));
		/* no switch is required -- saw@shade.msu.ru */
		vc->vt_newvt = -1;
		console_unlock();
		break;
	}

	case VT_GETMODE:
	{
		struct vt_mode tmp;
		int rc;

		console_lock();
		memcpy(&tmp, &vc->vt_mode, sizeof(struct vt_mode));
		console_unlock();

		rc = copy_to_user(up, &tmp, sizeof(struct vt_mode));
		if (rc)
			ret = -EFAULT;
		break;
	}

	/*
	 * Returns global vt state. Note that VT 0 is always open, since
	 * it's an alias for the current VT, and people can't use it here.
	 * We cannot return state for more than 16 VTs, since v_state is short.
	 */
	case VT_GETSTATE:
	{
		struct vt_stat __user *vtstat = up;
		unsigned short state, mask;

		/* Review: FIXME: Console lock ? */
		if (put_user(fg_console + 1, &vtstat->v_active))
			ret = -EFAULT;
		else {
			state = 1;	/* /dev/tty0 is always open */
			for (i = 0, mask = 2; i < MAX_NR_CONSOLES && mask;
							++i, mask <<= 1)
				if (((*klpe_console_driver)->ttys[i] && (*klpe_console_driver)->ttys[i]->count))
					state |= mask;
			ret = put_user(state, &vtstat->v_state);
		}
		break;
	}

	/*
	 * Returns the first available (non-opened) console.
	 */
	case VT_OPENQRY:
		/* FIXME: locking ? - but then this is a stupid API */
		for (i = 0; i < MAX_NR_CONSOLES; ++i)
			if (! ((*klpe_console_driver)->ttys[i] && (*klpe_console_driver)->ttys[i]->count))
				break;
		uival = i < MAX_NR_CONSOLES ? (i+1) : -1;
		goto setint;		 

	/*
	 * ioctl(fd, VT_ACTIVATE, num) will cause us to switch to vt # num,
	 * with num >= 1 (switches to vt 0, our console, are not allowed, just
	 * to preserve sanity).
	 */
	case VT_ACTIVATE:
		if (!perm)
			return -EPERM;
		if (arg == 0 || arg > MAX_NR_CONSOLES)
			ret =  -ENXIO;
		else {
			arg--;
			console_lock();
			ret = (*klpe_vc_allocate)(arg);
			console_unlock();
			if (ret)
				break;
			(*klpe_set_console)(arg);
		}
		break;

	case VT_SETACTIVATE:
	{
		struct vt_setactivate vsa;

		if (!perm)
			return -EPERM;

		if (copy_from_user(&vsa, (struct vt_setactivate __user *)arg,
					sizeof(struct vt_setactivate))) {
			ret = -EFAULT;
			goto out;
		}
		if (vsa.console == 0 || vsa.console > MAX_NR_CONSOLES)
			ret = -ENXIO;
		else {
			vsa.console = array_index_nospec(vsa.console,
							 MAX_NR_CONSOLES + 1);
			vsa.console--;
			console_lock();
			ret = (*klpe_vc_allocate)(vsa.console);
			if (ret == 0) {
				struct vc_data *nvc;
				/* This is safe providing we don't drop the
				   console sem between vc_allocate and
				   finishing referencing nvc */
				nvc = vc_cons[vsa.console].d;
				nvc->vt_mode = vsa.mode;
				nvc->vt_mode.frsig = 0;
				put_pid(nvc->vt_pid);
				nvc->vt_pid = get_pid(task_pid(current));
			}
			console_unlock();
			if (ret)
				break;
			/* Commence switch and lock */
			/* Review set_console locks */
			(*klpe_set_console)(vsa.console);
		}
		break;
	}

	/*
	 * wait until the specified VT has been activated
	 */
	case VT_WAITACTIVE:
		if (!perm)
			return -EPERM;
		if (arg == 0 || arg > MAX_NR_CONSOLES)
			ret = -ENXIO;
		else
			ret = (*klpe_vt_waitactive)(arg);
		break;

	/*
	 * If a vt is under process control, the kernel will not switch to it
	 * immediately, but postpone the operation until the process calls this
	 * ioctl, allowing the switch to complete.
	 *
	 * According to the X sources this is the behavior:
	 *	0:	pending switch-from not OK
	 *	1:	pending switch-from OK
	 *	2:	completed switch-to OK
	 */
	case VT_RELDISP:
		if (!perm)
			return -EPERM;

		console_lock();
		if (vc->vt_mode.mode != VT_PROCESS) {
			console_unlock();
			ret = -EINVAL;
			break;
		}
		/*
		 * Switching-from response
		 */
		if (vc->vt_newvt >= 0) {
			if (arg == 0)
				/*
				 * Switch disallowed, so forget we were trying
				 * to do it.
				 */
				vc->vt_newvt = -1;

			else {
				/*
				 * The current vt has been released, so
				 * complete the switch.
				 */
				int newvt;
				newvt = vc->vt_newvt;
				vc->vt_newvt = -1;
				ret = (*klpe_vc_allocate)(newvt);
				if (ret) {
					console_unlock();
					break;
				}
				/*
				 * When we actually do the console switch,
				 * make sure we are atomic with respect to
				 * other console switches..
				 */
				(*klpe_complete_change_console)(vc_cons[newvt].d);
			}
		} else {
			/*
			 * Switched-to response
			 */
			/*
			 * If it's just an ACK, ignore it
			 */
			if (arg != VT_ACKACQ)
				ret = -EINVAL;
		}
		console_unlock();
		break;

	 /*
	  * Disallocate memory associated to VT (but leave VT1)
	  */
	 case VT_DISALLOCATE:
		if (arg > MAX_NR_CONSOLES) {
			ret = -ENXIO;
			break;
		}
		if (arg == 0)
			(*klpe_vt_disallocate_all)();
		else
			ret = klpr_vt_disallocate(--arg);
		break;

	case VT_RESIZE:
	{
		struct vt_sizes __user *vtsizes = up;
		struct vc_data *vc;

		ushort ll,cc;
		if (!perm)
			return -EPERM;
		if (get_user(ll, &vtsizes->v_rows) ||
		    get_user(cc, &vtsizes->v_cols))
			ret = -EFAULT;
		else {
			console_lock();
			for (i = 0; i < MAX_NR_CONSOLES; i++) {
				vc = vc_cons[i].d;

				if (vc) {
					vc->vc_resize_user = 1;
					/* FIXME: review v tty lock */
					vc_resize(vc_cons[i].d, cc, ll);
				}
			}
			console_unlock();
		}
		break;
	}

	case VT_RESIZEX:
	{
		struct vt_consize v;
		if (!perm)
			return -EPERM;
		if (copy_from_user(&v, up, sizeof(struct vt_consize)))
			return -EFAULT;
		/* FIXME: Should check the copies properly */
		if (!v.v_vlin)
			v.v_vlin = vc->vc_scan_lines;
		if (v.v_clin) {
			int rows = v.v_vlin/v.v_clin;
			if (v.v_rows != rows) {
				if (v.v_rows) /* Parameters don't add up */
					return -EINVAL;
				v.v_rows = rows;
			}
		}
		if (v.v_vcol && v.v_ccol) {
			int cols = v.v_vcol/v.v_ccol;
			if (v.v_cols != cols) {
				if (v.v_cols)
					return -EINVAL;
				v.v_cols = cols;
			}
		}

		if (v.v_clin > 32)
			return -EINVAL;

		for (i = 0; i < MAX_NR_CONSOLES; i++) {
			struct vc_data *vcp;

			if (!vc_cons[i].d)
				continue;
			console_lock();
			vcp = vc_cons[i].d;
			if (vcp) {
				if (v.v_vlin)
					vcp->vc_scan_lines = v.v_vlin;
				if (v.v_clin)
					vcp->vc_font.height = v.v_clin;
				vcp->vc_resize_user = 1;
				vc_resize(vcp, v.v_cols, v.v_rows);
			}
			console_unlock();
		}
		break;
	}

	case PIO_FONT: {
		if (!perm)
			return -EPERM;
		op.op = KD_FONT_OP_SET;
		op.flags = KD_FONT_FLAG_OLD | KD_FONT_FLAG_DONT_RECALC;	/* Compatibility */
		op.width = 8;
		op.height = 0;
		op.charcount = 256;
		op.data = up;
		/*
		 * Fix CVE-2020-25668
		 *  -1 line, +1 line
		 */
		ret = (*klpe_con_font_op)(vc, &op);
		break;
	}

	case GIO_FONT: {
		op.op = KD_FONT_OP_GET;
		op.flags = KD_FONT_FLAG_OLD;
		op.width = 8;
		op.height = 32;
		op.charcount = 256;
		op.data = up;
		/*
		 * Fix CVE-2020-25668
		 *  -1 line, +1 line
		 */
		ret = (*klpe_con_font_op)(vc, &op);
		break;
	}

	case PIO_CMAP:
                if (!perm)
			ret = -EPERM;
		else
	                ret = (*klpe_con_set_cmap)(up);
		break;

	case GIO_CMAP:
                ret = (*klpe_con_get_cmap)(up);
		break;

	case PIO_FONTX:
	case GIO_FONTX:
		/*
		 * Fix CVE-2020-25668
		 *  -1 line, +1 line
		 */
		ret = klpp_do_fontx_ioctl(vc, cmd, up, perm, &op);
		break;

	case PIO_FONTRESET:
	{
		if (!perm)
			return -EPERM;

#ifdef BROKEN_GRAPHICS_PROGRAMS
		ret = -ENOSYS;
		break;
#else
		{
		op.op = KD_FONT_OP_SET_DEFAULT;
		op.data = NULL;
		/*
		 * Fix CVE-2020-25668
		 *  -1 line, +1 line
		 */
		ret = (*klpe_con_font_op)(vc, &op);
		if (ret)
			break;
		console_lock();
		/*
		 * Fix CVE-2020-25668
		 *  -1 line, +1 line
		 */
		con_set_default_unimap(vc);
		console_unlock();
		break;
		}
#endif
	}

	case KDFONTOP: {
		if (copy_from_user(&op, up, sizeof(op))) {
			ret = -EFAULT;
			break;
		}
		if (!perm && op.op != KD_FONT_OP_GET)
			return -EPERM;
		ret = (*klpe_con_font_op)(vc, &op);
		if (ret)
			break;
		if (copy_to_user(up, &op, sizeof(op)))
			ret = -EFAULT;
		break;
	}

	case PIO_SCRNMAP:
		if (!perm)
			ret = -EPERM;
		else
			ret = (*klpe_con_set_trans_old)(up);
		break;

	case GIO_SCRNMAP:
		ret = (*klpe_con_get_trans_old)(up);
		break;

	case PIO_UNISCRNMAP:
		if (!perm)
			ret = -EPERM;
		else
			ret = (*klpe_con_set_trans_new)(up);
		break;

	case GIO_UNISCRNMAP:
		ret = (*klpe_con_get_trans_new)(up);
		break;

	case PIO_UNIMAPCLR:
		if (!perm)
			return -EPERM;
		(*klpe_con_clear_unimap)(vc);
		break;

	case PIO_UNIMAP:
	case GIO_UNIMAP:
		ret = klpr_do_unimap_ioctl(cmd, up, perm, vc);
		break;

	case VT_LOCKSWITCH:
		if (!capable(CAP_SYS_TTY_CONFIG))
			return -EPERM;
		(*klpe_vt_dont_switch) = 1;
		break;
	case VT_UNLOCKSWITCH:
		if (!capable(CAP_SYS_TTY_CONFIG))
			return -EPERM;
		(*klpe_vt_dont_switch) = 0;
		break;
	case VT_GETHIFONTMASK:
		ret = put_user(vc->vc_hi_font_mask,
					(unsigned short __user *)arg);
		break;
	case VT_WAITEVENT:
		ret = klpr_vt_event_wait_ioctl((struct vt_event __user *)arg);
		break;
	default:
		ret = -ENOIOCTLCMD;
	}
out:
	return ret;
}

#ifdef CONFIG_COMPAT

struct compat_consolefontdesc {
	unsigned short charcount;       /* characters in font (256 or 512) */
	unsigned short charheight;      /* scan lines per character (1-32) */
	compat_caddr_t chardata;	/* font data in expanded form */
};

static inline int
/*
 * Fix CVE-2020-25668
 *  -1 line, +2 lines
 */
klpp_compat_fontx_ioctl(struct vc_data *vc, int cmd,
			struct compat_consolefontdesc __user *user_cfd,
			int perm, struct console_font_op *op)
{
	struct compat_consolefontdesc cfdarg;
	int i;

	if (copy_from_user(&cfdarg, user_cfd, sizeof(struct compat_consolefontdesc)))
		return -EFAULT;

	switch (cmd) {
	case PIO_FONTX:
		if (!perm)
			return -EPERM;
		op->op = KD_FONT_OP_SET;
		op->flags = KD_FONT_FLAG_OLD;
		op->width = 8;
		op->height = cfdarg.charheight;
		op->charcount = cfdarg.charcount;
		op->data = compat_ptr(cfdarg.chardata);
		/*
		 * Fix CVE-2020-25668
		 *  -1 line, +1 line
		 */
		return (*klpe_con_font_op)(vc, op);
	case GIO_FONTX:
		op->op = KD_FONT_OP_GET;
		op->flags = KD_FONT_FLAG_OLD;
		op->width = 8;
		op->height = cfdarg.charheight;
		op->charcount = cfdarg.charcount;
		op->data = compat_ptr(cfdarg.chardata);
		/*
		 * Fix CVE-2020-25668
		 *  -1 line, +1 line
		 */
		i = (*klpe_con_font_op)(vc, op);
		if (i)
			return i;
		cfdarg.charheight = op->height;
		cfdarg.charcount = op->charcount;
		if (copy_to_user(user_cfd, &cfdarg, sizeof(struct compat_consolefontdesc)))
			return -EFAULT;
		return 0;
	}
	return -EINVAL;
}

struct compat_console_font_op {
	compat_uint_t op;        /* operation code KD_FONT_OP_* */
	compat_uint_t flags;     /* KD_FONT_FLAG_* */
	compat_uint_t width, height;     /* font size */
	compat_uint_t charcount;
	compat_caddr_t data;    /* font data with height fixed to 32 */
};

static inline int
klpr_compat_kdfontop_ioctl(struct compat_console_font_op __user *fontop,
			 int perm, struct console_font_op *op, struct vc_data *vc)
{
	int i;

	if (copy_from_user(op, fontop, sizeof(struct compat_console_font_op)))
		return -EFAULT;
	if (!perm && op->op != KD_FONT_OP_GET)
		return -EPERM;
	op->data = compat_ptr(((struct compat_console_font_op *)op)->data);
	i = (*klpe_con_font_op)(vc, op);
	if (i)
		return i;
	((struct compat_console_font_op *)op)->data = (unsigned long)op->data;
	if (copy_to_user(fontop, op, sizeof(struct compat_console_font_op)))
		return -EFAULT;
	return 0;
}

struct compat_unimapdesc {
	unsigned short entry_ct;
	compat_caddr_t entries;
};

static inline int
klpr_compat_unimap_ioctl(unsigned int cmd, struct compat_unimapdesc __user *user_ud,
			 int perm, struct vc_data *vc)
{
	struct compat_unimapdesc tmp;
	struct unipair __user *tmp_entries;

	if (copy_from_user(&tmp, user_ud, sizeof tmp))
		return -EFAULT;
	tmp_entries = compat_ptr(tmp.entries);
	switch (cmd) {
	case PIO_UNIMAP:
		if (!perm)
			return -EPERM;
		return (*klpe_con_set_unimap)(vc, tmp.entry_ct, tmp_entries);
	case GIO_UNIMAP:
		if (!perm && fg_console != vc->vc_num)
			return -EPERM;
		return (*klpe_con_get_unimap)(vc, tmp.entry_ct, &(user_ud->entry_ct), tmp_entries);
	}
	return 0;
}

long klpp_vt_compat_ioctl(struct tty_struct *tty,
	     unsigned int cmd, unsigned long arg)
{
	struct vc_data *vc = tty->driver_data;
	struct console_font_op op;	/* used in multiple places here */
	unsigned int console = vc->vc_num;
	void __user *up = compat_ptr(arg);
	int perm;


	if (!(*klpe_vc_cons_allocated)(console)) 	/* impossible? */
		return -ENOIOCTLCMD;

	/*
	 * To have permissions to do most of the vt ioctls, we either have
	 * to be the owner of the tty, or have CAP_SYS_TTY_CONFIG.
	 */
	perm = 0;
	if (current->signal->tty == tty || capable(CAP_SYS_TTY_CONFIG))
		perm = 1;

	switch (cmd) {
	/*
	 * these need special handlers for incompatible data structures
	 */
	case PIO_FONTX:
	case GIO_FONTX:
		/*
		 * Fix CVE-2020-25668
		 *  -1 line, +1 line
		 */
		return klpp_compat_fontx_ioctl(vc, cmd, up, perm, &op);

	case KDFONTOP:
		return klpr_compat_kdfontop_ioctl(up, perm, &op, vc);

	case PIO_UNIMAP:
	case GIO_UNIMAP:
		return klpr_compat_unimap_ioctl(cmd, up, perm, vc);

	/*
	 * all these treat 'arg' as an integer
	 */
	case KIOCSOUND:
	case KDMKTONE:
#ifdef CONFIG_X86
	case KDADDIO:
	case KDDELIO:
#endif
	case KDSETMODE:
	case KDMAPDISP:
	case KDUNMAPDISP:
	case KDSKBMODE:
	case KDSKBMETA:
	case KDSKBLED:
	case KDSETLED:
	case KDSIGACCEPT:
	case VT_ACTIVATE:
	case VT_WAITACTIVE:
	case VT_RELDISP:
	case VT_DISALLOCATE:
	case VT_RESIZE:
	case VT_RESIZEX:
		return klpp_vt_ioctl(tty, cmd, arg);

	/*
	 * the rest has a compatible data structure behind arg,
	 * but we have to convert it to a proper 64 bit pointer.
	 */
	default:
		return klpp_vt_ioctl(tty, cmd, (unsigned long)up);
	}
}

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_COMPAT */



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "vt_dont_switch", (void *)&klpe_vt_dont_switch },
	{ "sel_cons", (void *)&klpe_sel_cons },
	{ "vt_spawn_con", (void *)&klpe_vt_spawn_con },
	{ "console_driver", (void *)&klpe_console_driver },
	{ "set_console", (void *)&klpe_set_console },
	{ "kbd_rate", (void *)&klpe_kbd_rate },
	{ "vc_allocate", (void *)&klpe_vc_allocate },
	{ "vc_cons_allocated", (void *)&klpe_vc_cons_allocated },
	{ "vc_deallocate", (void *)&klpe_vc_deallocate },
	{ "con_font_op", (void *)&klpe_con_font_op },
	{ "con_set_cmap", (void *)&klpe_con_set_cmap },
	{ "con_get_cmap", (void *)&klpe_con_get_cmap },
	{ "tioclinux", (void *)&klpe_tioclinux },
	{ "con_set_trans_old", (void *)&klpe_con_set_trans_old },
	{ "con_get_trans_old", (void *)&klpe_con_get_trans_old },
	{ "con_set_trans_new", (void *)&klpe_con_set_trans_new },
	{ "con_get_trans_new", (void *)&klpe_con_get_trans_new },
	{ "con_clear_unimap", (void *)&klpe_con_clear_unimap },
	{ "con_set_unimap", (void *)&klpe_con_set_unimap },
	{ "con_get_unimap", (void *)&klpe_con_get_unimap },
	{ "vt_waitactive", (void *)&klpe_vt_waitactive },
	{ "complete_change_console", (void *)&klpe_complete_change_console },
	{ "vt_do_diacrit", (void *)&klpe_vt_do_diacrit },
	{ "vt_do_kdskbmode", (void *)&klpe_vt_do_kdskbmode },
	{ "vt_do_kdskbmeta", (void *)&klpe_vt_do_kdskbmeta },
	{ "vt_do_kbkeycode_ioctl", (void *)&klpe_vt_do_kbkeycode_ioctl },
	{ "vt_do_kdsk_ioctl", (void *)&klpe_vt_do_kdsk_ioctl },
	{ "vt_do_kdgkb_ioctl", (void *)&klpe_vt_do_kdgkb_ioctl },
	{ "vt_do_kdskled", (void *)&klpe_vt_do_kdskled },
	{ "vt_do_kdgkbmode", (void *)&klpe_vt_do_kdgkbmode },
	{ "vt_do_kdgkbmeta", (void *)&klpe_vt_do_kdgkbmeta },
#ifdef CONFIG_X86
	{ "ksys_ioperm", (void *)&klpe_ksys_ioperm },
#endif
	{ "vt_disallocate_all", (void *)&klpe_vt_disallocate_all },
	{ "vt_events", (void *)&klpe_vt_events },
	{ "vt_event_lock", (void *)&klpe_vt_event_lock },
	{ "vt_event_waitqueue", (void *)&klpe_vt_event_waitqueue },
};

int livepatch_bsc1178622_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_VT) */
