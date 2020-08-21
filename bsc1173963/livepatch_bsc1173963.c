/*
 * livepatch_bsc1173963
 *
 * Fix for CVE-2019-9458, bsc#1173963
 *
 *  Upstream commits:
 *  ad608fbcf166 ("media: v4l: event: Prevent freeing event subscriptions while
 *                 accessed")
 *  92539d3eda2c ("media: v4l: event: Add subscription to list before calling
 *                 "add" operation")
 *
 *  SLE12-SP2 and -SP3 commits:
 *  249de3c69975b15a4ac1f64f45e496229ab92ca8
 *  5d70526fda02fc81108caf1d7c5737c29cc7cf73
 *  81cd7447342b9a710d0dba98b6497bf6370d338d
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  d54422bfa9109192cebe18a2fed89b35704bb428
 *  4eff58ad7eb32b21cfeacbe0f7f62536659648e2
 *  c4ab1548fe032194682607ccae128e0df72fca09
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

#if IS_ENABLED(CONFIG_VIDEO_V4L2)

#if !IS_MODULE(CONFIG_VIDEO_V4L2)
#error "Live patch supports only CONFIG_VIDEO_V4L2=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/livepatch.h>
#include "livepatch_bsc1173963.h"
#include "../kallsyms_relocs.h"
#include "../shadow.h"

#define LIVEPATCHED_MODULE "videodev"


#define KLP_BSC1173963_SHARED_STATE_ID KLP_SHADOW_ID(1173963, 0)

/* Protected by module_mutex. */
struct klp_bsc1173963_shared_state
{
	unsigned long refcount;
	struct mutex v4l2_fh_subscribe_lock;
};

static struct klp_bsc1173963_shared_state *klp_bsc1173963_shared_state;



/* klp-ccp: from drivers/media/v4l2-core/v4l2-event.c */
#include <media/v4l2-dev.h>
#include <media/v4l2-fh.h>
#include <media/v4l2-event.h>

/* klp-ccp: from include/media/v4l2-event.h */
int klpp_v4l2_event_subscribe(struct v4l2_fh *fh,
			 const struct v4l2_event_subscription *sub,
			 unsigned int elems,
			 const struct v4l2_subscribed_event_ops *ops);

int klpp_v4l2_event_unsubscribe(struct v4l2_fh *fh,
			   const struct v4l2_event_subscription *sub);

static void (*klpe_v4l2_event_unsubscribe_all)(struct v4l2_fh *fh);

int klpp_v4l2_event_subdev_unsubscribe(struct v4l2_subdev *sd,
				  struct v4l2_fh *fh,
				  struct v4l2_event_subscription *sub);

/* klp-ccp: from drivers/media/v4l2-core/v4l2-event.c */
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/export.h>

static unsigned sev_pos(const struct v4l2_subscribed_event *sev, unsigned idx)
{
	idx += sev->first;
	return idx >= sev->elems ? idx - sev->elems : idx;
}

static struct v4l2_subscribed_event *(*klpe_v4l2_event_subscribed)(
		struct v4l2_fh *fh, u32 type, u32 id);

/* New */
static void klpp___v4l2_event_unsubscribe(struct v4l2_subscribed_event *sev)
{
	struct v4l2_fh *fh = sev->fh;
	unsigned int i;

	lockdep_assert_held(&klp_bsc1173963_shared_state->v4l2_fh_subscribe_lock);
	assert_spin_locked(&fh->vdev->fh_lock);

	/* Remove any pending events for this subscription */
	for (i = 0; i < sev->in_use; i++) {
		list_del(&sev->events[sev_pos(sev, i)].list);
		fh->navailable--;
	}
	list_del(&sev->list);
}

int klpp_v4l2_event_subscribe(struct v4l2_fh *fh,
			 const struct v4l2_event_subscription *sub, unsigned elems,
			 const struct v4l2_subscribed_event_ops *ops)
{
	struct v4l2_subscribed_event *sev, *found_ev;
	unsigned long flags;
	unsigned i;
	/*
	 * Fix CVE-2019-9458
	 *  +1 line
	 */
	int ret = 0;

	if (sub->type == V4L2_EVENT_ALL)
		return -EINVAL;

	if (elems < 1)
		elems = 1;

	sev = kzalloc(sizeof(*sev) + sizeof(struct v4l2_kevent) * elems, GFP_KERNEL);
	if (!sev)
		return -ENOMEM;
	for (i = 0; i < elems; i++)
		sev->events[i].sev = sev;
	sev->type = sub->type;
	sev->id = sub->id;
	sev->flags = sub->flags;
	sev->fh = fh;
	sev->ops = ops;
	sev->ops = ops;
	/*
	 * Fix CVE-2019-9458
	 *  +/- 0 lines
	 *
	 * Upstreams moves the initialization of ->elems to here, but
	 * we deviate and don't do that. First note that upstream also
	 * removes the !->elems early return from
	 * __v4l2_event_queue_fh(), but we can't do that from a LP
	 * anyway (and it's not needed either). In any case, setting
	 * ->elems at this point already implies a semantic change as
	 * events could get queued as soon as this subscription here
	 * has been added to the fh->subscribed list below. Consumers
	 * might or might not be ready to handle those at the time
	 * their ->add callback hasn't returned yet. Be conservative
	 * and retain the old behaviour.
	 */

	/*
	 * Fix CVE-2019-9458
	 *  +1 line
	 */
	mutex_lock(&klp_bsc1173963_shared_state->v4l2_fh_subscribe_lock);

	spin_lock_irqsave(&fh->vdev->fh_lock, flags);
	found_ev = (*klpe_v4l2_event_subscribed)(fh, sub->type, sub->id);
	if (!found_ev)
		list_add(&sev->list, &fh->subscribed);
	spin_unlock_irqrestore(&fh->vdev->fh_lock, flags);

	/*
	 * Fix CVE-2019-9458
	 *  -13 lines, +20 lines
	 */
	if (found_ev) {
		kfree(sev);
	} else if (sev->ops && sev->ops->add) {
		ret = sev->ops->add(sev, elems);
		if (ret) {
			spin_lock_irqsave(&fh->vdev->fh_lock, flags);
			/*
			 * This is again different from upstream and
			 * protects against unpatched
			 * v4l2_event_unsubscribe() freeing sev from under
			 * us during the livepatching transition.
			 */
			found_ev = (*klpe_v4l2_event_subscribed)(fh, sub->type, sub->id);
			if (found_ev == sev)
				klpp___v4l2_event_unsubscribe(sev);
			spin_unlock_irqrestore(&fh->vdev->fh_lock, flags);
			if (found_ev == sev)
				kfree(sev);
		}
	}

	/* Mark as ready for use */
	/*
	 * Fix CVE-2019-9458
	 *  -1 line, +2 lines
	 *
	 * As explained above, we deviate from upstream as for when
	 * ->elems gets set. The above branches for found_ev || ret
	 * used to return early and thus, the assignment below would
	 * not have been reached in this case.
	 */
	if (!found_ev && !ret)
		sev->elems = elems;

	/*
	 * Fix CVE-2019-9458
	 *  +1 line
	 */
	mutex_unlock(&klp_bsc1173963_shared_state->v4l2_fh_subscribe_lock);

	/*
	 * Fix CVE-2019-9458
	 *  -1 line, +1 line
	 */
	return ret;
}

int klpp_v4l2_event_unsubscribe(struct v4l2_fh *fh,
			   const struct v4l2_event_subscription *sub)
{
	struct v4l2_subscribed_event *sev;
	unsigned long flags;
	/*
	 * Fix CVE-2019-9458
	 *  -1 line
	 */

	if (sub->type == V4L2_EVENT_ALL) {
		(*klpe_v4l2_event_unsubscribe_all)(fh);
		return 0;
	}

	/*
	 * Fix CVE-2019-9458
	 *  +1 line
	 */
	mutex_lock(&klp_bsc1173963_shared_state->v4l2_fh_subscribe_lock);

	spin_lock_irqsave(&fh->vdev->fh_lock, flags);

	sev = (*klpe_v4l2_event_subscribed)(fh, sub->type, sub->id);
	/*
	 * Fix CVE-2019-9458
	 *  -8 lines, +2 lines (actually an identity transformation)
	 */
	if (sev != NULL)
		klpp___v4l2_event_unsubscribe(sev);

	spin_unlock_irqrestore(&fh->vdev->fh_lock, flags);

	if (sev && sev->ops && sev->ops->del)
		sev->ops->del(sev);

	/*
	 * Fix CVE-2019-9458
	 *  +1 line
	 */
	mutex_unlock(&klp_bsc1173963_shared_state->v4l2_fh_subscribe_lock);

	kfree(sev);

	return 0;
}

int klpp_v4l2_event_subdev_unsubscribe(struct v4l2_subdev *sd, struct v4l2_fh *fh,
				  struct v4l2_event_subscription *sub)
{
	return klpp_v4l2_event_unsubscribe(fh, sub);
}



static int klp_bsc1173963_init_shared_state(void *obj,
					    void *shadow_data,
					    void *ctor_dat)
{
	struct klp_bsc1173963_shared_state *s = shadow_data;

	memset(s, 0, sizeof(*s));
	mutex_init(&s->v4l2_fh_subscribe_lock);

	return 0;
}

static void klp_bsc1173963_destroy_shared_state(void *obj,
					       void *shadow_data)
{
	struct klp_bsc1173963_shared_state *s = shadow_data;

	mutex_destroy(&s->v4l2_fh_subscribe_lock);
}

/* Must be called with module_mutex held. */
static int __klp_bsc1173963_get_shared_state(void)
{
	klp_bsc1173963_shared_state =
		klp_shadow_get_or_alloc(NULL, KLP_BSC1173963_SHARED_STATE_ID,
					sizeof(*klp_bsc1173963_shared_state),
					GFP_KERNEL,
					klp_bsc1173963_init_shared_state, NULL);
	if (!klp_bsc1173963_shared_state)
		return -ENOMEM;

	++klp_bsc1173963_shared_state->refcount;

	return 0;
}

/* Must be called with module_mutex held. */
static void __klp_bsc1173963_put_shared_state(void)
{
	--klp_bsc1173963_shared_state->refcount;
	if (!klp_bsc1173963_shared_state->refcount) {
		klp_shadow_free(NULL, KLP_BSC1173963_SHARED_STATE_ID,
				klp_bsc1173963_destroy_shared_state);
	}

	klp_bsc1173963_shared_state = NULL;
}


static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "v4l2_event_unsubscribe_all",
	  (void *)&klpe_v4l2_event_unsubscribe_all, "videodev" },
	{ "v4l2_event_subscribed", (void *)&klpe_v4l2_event_subscribed,
	  "videodev" },
};

static int livepatch_bsc1173963_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1173963_module_nb = {
	.notifier_call = livepatch_bsc1173963_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1173963_init(void)
{
	int ret;

	mutex_lock(&module_mutex);

	ret = __klp_bsc1173963_get_shared_state();
	if (ret)
		goto out;

	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret) {
			__klp_bsc1173963_put_shared_state();
			goto out;
		}
	}

	ret = register_module_notifier(&livepatch_bsc1173963_module_nb);
	if (ret)
		__klp_bsc1173963_put_shared_state();
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1173963_cleanup(void)
{
	mutex_lock(&module_mutex);
	__klp_bsc1173963_put_shared_state();
	mutex_unlock(&module_mutex);

	unregister_module_notifier(&livepatch_bsc1173963_module_nb);
}

#endif /* IS_ENABLED(CONFIG_VIDEO_V4L2) */
