#ifndef _LIVEPATCH_BSC1173942_H
#define _LIVEPATCH_BSC1173942_H

#if IS_ENABLED(CONFIG_USB_GSPCA_XIRLINK_CIT)

int livepatch_bsc1173942_init(void);
void livepatch_bsc1173942_cleanup(void);


struct gspca_dev;

int klpp_cit_get_packet_size(struct gspca_dev *gspca_dev);
int klpp_sd_isoc_init(struct gspca_dev *gspca_dev);

#else /* !IS_ENABLED(CONFIG_USB_GSPCA_XIRLINK_CIT) */

static inline int livepatch_bsc1173942_init(void) { return 0; }

static inline void livepatch_bsc1173942_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_USB_GSPCA_XIRLINK_CIT) */
#endif /* _LIVEPATCH_BSC1173942_H */
