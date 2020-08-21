#ifndef _LIVEPATCH_BSC1173934_H
#define _LIVEPATCH_BSC1173934_H

#if IS_ENABLED(CONFIG_SND_USB_AUDIO)

int livepatch_bsc1173934_init(void);
void livepatch_bsc1173934_cleanup(void);


struct mixer_build;

int klpp_parse_audio_mixer_unit(struct mixer_build *state, int unitid,
				  void *raw_desc);

#else /* !IS_ENABLED(CONFIG_SND_USB_AUDIO) */

static inline int livepatch_bsc1173934_init(void) { return 0; }

static inline void livepatch_bsc1173934_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SND_USB_AUDIO) */
#endif /* _LIVEPATCH_BSC1173934_H */
