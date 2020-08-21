#ifndef _LIVEPATCH_BSC1174247_H
#define _LIVEPATCH_BSC1174247_H

#if IS_ENABLED(CONFIG_VGA_CONSOLE)

int livepatch_bsc1174247_init(void);
static inline void livepatch_bsc1174247_cleanup(void) {}

struct vc_data;
enum con_scroll;

bool klpp_vgacon_scroll(struct vc_data *c, unsigned int t, unsigned int b,
		enum con_scroll dir, unsigned int lines);

#else /* !IS_ENABLED(CONFIG_VGA_CONSOLE) */

static inline int livepatch_bsc1174247_init(void) { return 0; }

static inline void livepatch_bsc1174247_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_VGA_CONSOLE) */
#endif /* _LIVEPATCH_BSC1174247_H */
