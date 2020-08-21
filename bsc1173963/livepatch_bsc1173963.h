#ifndef _LIVEPATCH_BSC1173963_H
#define _LIVEPATCH_BSC1173963_H

#if IS_ENABLED(CONFIG_VIDEO_V4L2)

int livepatch_bsc1173963_init(void);
void livepatch_bsc1173963_cleanup(void);


struct v4l2_fh;
struct v4l2_event_subscription;
struct v4l2_subscribed_event_ops;

int klpp_v4l2_event_subscribe(struct v4l2_fh *fh,
			 const struct v4l2_event_subscription *sub,
			 unsigned int elems,
			 const struct v4l2_subscribed_event_ops *ops);

int klpp_v4l2_event_unsubscribe(struct v4l2_fh *fh,
			   const struct v4l2_event_subscription *sub);

#else /* !IS_ENABLED(CONFIG_VIDEO_V4L2) */

static inline int livepatch_bsc1173963_init(void) { return 0; }

static inline void livepatch_bsc1173963_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_VIDEO_V4L2) */
#endif /* _LIVEPATCH_BSC1173963_H */
