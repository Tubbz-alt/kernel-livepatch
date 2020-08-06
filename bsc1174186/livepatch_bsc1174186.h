#ifndef _LIVEPATCH_BSC1174186_H
#define _LIVEPATCH_BSC1174186_H

#if IS_ENABLED(CONFIG_ACPI_CONFIGFS)

struct config_item;

ssize_t klpp_acpi_table_aml_write(struct config_item *cfg,
				    const void *data, size_t size);

#endif /* IS_ENABLED(CONFIG_ACPI_CONFIGFS) */

static inline int livepatch_bsc1174186_init(void) { return 0; }

static inline void livepatch_bsc1174186_cleanup(void) {}

#endif /* _LIVEPATCH_BSC1174186_H */
