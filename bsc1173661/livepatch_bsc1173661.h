#ifndef _LIVEPATCH_BSC1173661_H
#define _LIVEPATCH_BSC1173661_H

#if IS_ENABLED(CONFIG_MWIFIEX)

int livepatch_bsc1173661_init(void);
void livepatch_bsc1173661_cleanup(void);


struct mwifiex_private;

void klpp_mwifiex_process_tdls_action_frame(struct mwifiex_private *priv,
				       u8 *buf, int len);

#else /* !IS_ENABLED(CONFIG_MWIFIEX) */

static inline int livepatch_bsc1173661_init(void) { return 0; }

static inline void livepatch_bsc1173661_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_MWIFIEX) */
#endif /* _LIVEPATCH_BSC1173661_H */
