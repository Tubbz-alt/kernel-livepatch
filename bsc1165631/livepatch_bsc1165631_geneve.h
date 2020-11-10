#ifndef _LIVEPATCH_BSC1165631_GENEVE_H
#define _LIVEPATCH_BSC1165631_GENEVE_H

int livepatch_bsc1165631_geneve_init(void);
void livepatch_bsc1165631_geneve_cleanup(void);


#include <linux/netdevice.h>
struct sk_buff;

netdev_tx_t klpp_geneve_xmit(struct sk_buff *skb, struct net_device *dev);
int klpp_geneve_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb);

#endif /* _LIVEPATCH_BSC1165631_GENEVE_H */
