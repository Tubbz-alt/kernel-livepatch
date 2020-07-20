#ifndef _LIVEPATCH_BSC1173659_H
#define _LIVEPATCH_BSC1173659_H

#if IS_ENABLED(CONFIG_CFG80211)

int livepatch_bsc1173659_init(void);
void livepatch_bsc1173659_cleanup(void);


struct nlattr;
struct cfg80211_beacon_data;

int klpp_nl80211_parse_beacon(struct nlattr *attrs[],
				struct cfg80211_beacon_data *bcn);

#else /* !IS_ENABLED(CONFIG_CFG80211) */

static inline int livepatch_bsc1173659_init(void) { return 0; }

static inline void livepatch_bsc1173659_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_CFG80211) */
#endif /* _LIVEPATCH_BSC1173659_H */
