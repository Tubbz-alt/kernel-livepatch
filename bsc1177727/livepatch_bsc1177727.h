#ifndef _LIVEPATCH_BSC1177727_H
#define _LIVEPATCH_BSC1177727_H

#if IS_ENABLED(CONFIG_BT)

int livepatch_bsc1177727_init(void);
void livepatch_bsc1177727_cleanup(void);


struct hci_dev;
struct sk_buff;

void klpp_hci_le_meta_evt(struct hci_dev *hdev, struct sk_buff *skb);

#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1177727_init(void) { return 0; }

static inline void livepatch_bsc1177727_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT) */
#endif /* _LIVEPATCH_BSC1177727_H */
