#ifndef _LIVEPATCH_BSC1173100_H
#define _LIVEPATCH_BSC1173100_H

#if IS_ENABLED(CONFIG_MWIFIEX)

int livepatch_bsc1173100_init(void);
void livepatch_bsc1173100_cleanup(void);


struct mwifiex_private;
struct cfg80211_bss;
struct cfg80211_ssid;

int klpp_mwifiex_bss_start(struct mwifiex_private *priv, struct cfg80211_bss *bss,
		      struct cfg80211_ssid *req_ssid);

#else /* !IS_ENABLED(CONFIG_MWIFIEX) */

static inline int livepatch_bsc1173100_init(void) { return 0; }

static inline void livepatch_bsc1173100_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_MWIFIEX) */
#endif /* _LIVEPATCH_BSC1173100_H */
