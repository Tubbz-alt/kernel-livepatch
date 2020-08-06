/*
 * livepatch_bsc1174186
 *
 * Fix for CVE-2020-15780, bsc#1174186
 *
 *  Upstream commit:
 *  75b0cea7bf30 ("ACPI: configfs: Disallow loading ACPI tables when locked
 *                 down")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  0f0fd84f873e7a9050407fbfd9d7b0ca89f949eb
 *
 *  SLE15-SP2 commit:
 *  c89c5f3cd687e7a6cc5d5988979e4fe79a771467
 *
 *
 *  Copyright (c) 2020 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if IS_ENABLED(CONFIG_ACPI_CONFIGFS)

#if !IS_MODULE(CONFIG_ACPI_CONFIGFS)
#error "Live patch supports only CONFIG_ACPI_CONFIGFS=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1174186.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "acpi_configfs"

/* klp-ccp: from drivers/acpi/acpi_configfs.c */
#define pr_fmt(fmt) "ACPI configfs: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/configfs.h>
#include <linux/acpi.h>
/* klp-ccp: from drivers/acpi/acpica/accommon.h */
#include <acpi/acconfig.h>	/* Global configuration constants */

/* klp-ccp: from drivers/acpi/acpica/actables.h */
acpi_status
acpi_tb_install_and_load_table(acpi_physical_address address,
			       u8 flags, u8 override, u32 *table_index);

/* klp-ccp: from drivers/acpi/acpi_configfs.c */
struct acpi_table {
	struct config_item cfg;
	struct acpi_table_header *header;
	u32 index;
};

ssize_t klpp_acpi_table_aml_write(struct config_item *cfg,
				    const void *data, size_t size)
{
	const struct acpi_table_header *header = data;
	struct acpi_table *table;
	int ret;

	/*
	 * Fix CVE-2020-15780
	 *  +3 lines
	 */
	if (kernel_is_locked_down())
		return -EPERM;

	table = container_of(cfg, struct acpi_table, cfg);

	if (table->header) {
		pr_err("table already loaded\n");
		return -EBUSY;
	}

	if (header->length != size) {
		pr_err("invalid table length\n");
		return -EINVAL;
	}

	if (memcmp(header->signature, ACPI_SIG_SSDT, 4)) {
		pr_err("invalid table signature\n");
		return -EINVAL;
	}

	table = container_of(cfg, struct acpi_table, cfg);

	table->header = kmemdup(header, header->length, GFP_KERNEL);
	if (!table->header)
		return -ENOMEM;

	ACPI_INFO(("Host-directed Dynamic ACPI Table Load:"));
	ret = acpi_tb_install_and_load_table(
			ACPI_PTR_TO_PHYSADDR(table->header),
			ACPI_TABLE_ORIGIN_EXTERNAL_VIRTUAL, FALSE,
			&table->index);
	if (ret) {
		kfree(table->header);
		table->header = NULL;
	}

	return ret;
}

#endif /* IS_ENABLED(CONFIG_ACPI_CONFIGFS) */
