#ifndef _LIVEPATCH_BSC1177729_H
#define _LIVEPATCH_BSC1177729_H

#if IS_ENABLED(CONFIG_BT)

int livepatch_bsc1177729_init(void);
void livepatch_bsc1177729_cleanup(void);


struct l2cap_conn;
struct sk_buff;

void klpp_l2cap_data_channel(struct l2cap_conn *conn, u16 cid,
			       struct sk_buff *skb);

#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1177729_init(void) { return 0; }

static inline void livepatch_bsc1177729_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT) */
#endif /* _LIVEPATCH_BSC1177729_H */
