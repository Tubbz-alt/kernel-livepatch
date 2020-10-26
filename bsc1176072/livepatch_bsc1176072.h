#ifndef _LIVEPATCH_BSC1176072_H
#define _LIVEPATCH_BSC1176072_H

int livepatch_bsc1176072_init(void);
void livepatch_bsc1176072_cleanup(void);


struct sk_buff;
struct net_device;
struct packet_type;

int klpp_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
		       struct packet_type *pt, struct net_device *orig_dev);

#endif /* _LIVEPATCH_BSC1176072_H */
