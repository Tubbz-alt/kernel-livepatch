#ifndef _LIVEPATCH_BSC1176896_H
#define _LIVEPATCH_BSC1176896_H

#if IS_ENABLED(CONFIG_HID)

int livepatch_bsc1176896_init(void);
static inline void livepatch_bsc1176896_cleanup(void) {}


struct hid_input;
struct hid_field;
struct hid_usage;

void klpp_hidinput_configure_usage(struct hid_input *hidinput, struct hid_field *field,
				     struct hid_usage *usage);

#else /* !IS_ENABLED(CONFIG_HID) */

static inline int livepatch_bsc1176896_init(void) { return 0; }

static inline void livepatch_bsc1176896_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_HID) */
#endif /* _LIVEPATCH_BSC1176896_H */
