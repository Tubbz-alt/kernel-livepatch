/*
 * livepatch_bsc1173663
 *
 * Fix for CVE-2019-0155, bsc#1173663
 *
 *  Upstream commits:
 *  25dda4dabeeb ("drm/i915/gtt: Add read only pages to gen8_pte_encode")
 *  250f8c8140ac ("drm/i915/gtt: Read-only pages for insert_entries on bdw+")
 *  c9e666880de5 ("drm/i915/gtt: Disable read-only support under GVT")
 *  3e977ac6179b ("drm/i915: Prevent writing into a read-only object via a GGTT
 *                 mmap")
 *  0a2f661b6c21 ("drm/i915: Rename gen7 cmdparser tables")
 *  44157641d448 ("drm/i915: Disable Secure Batches for gen6+")
 *  66d8aba1cd6d ("drm/i915: Remove Master tables from cmdparser")
 *  311a50e76a33 ("drm/i915: Add support for mandatory cmdparsing")
 *  4f7af1948abc ("drm/i915: Support ro ppgtt mapped cmdparser shadow buffers")
 *  435e8fc059db ("drm/i915: Allow parsing of unsized batches")
 *  0f2f39758341 ("drm/i915: Add gen9 BCS cmdparsing")
 *  0546a29cd884 ("drm/i915/cmdparser: Use explicit goto for error paths")
 *  f8c08d8faee5 ("drm/i915/cmdparser: Add support for backward jumps")
 *  926abff21a8f ("drm/i915/cmdparser: Ignore Length operands during command
 *                 matching")
 *  1d85a299c4db ("drm/i915: Lower RM timeout to avoid DSI hard hangs")
 *  7e34f4e4aad3 ("drm/i915/gen8+: Add RC6 CTX corruption WA")
 *  ea0b163b13ff ("drm/i915/cmdparser: Fix jump whitelist clearing")
 *  e5ee4956f2fd ("drm/i915/gtt: Revert "Disable read-only support under GVT")
 *
 *  cve/linux-4.4 commits:
 *  2419bcb950528fee0e7679717516c714ac2c3784
 *  ecadb2864ae28c4fe86462d33e4a2ef757d3878d
 *  1b3d9a3031322fcefd6890910562af476e0f0617
 *  58a406353f1b72ba942ab2a9df9ac3f8d86f29a5
 *  6839fffce423f4097f06333cd0e073ee5f38a816
 *  6d2d4809bf5da751e7e529e3c0f87008cba79386
 *  bca86141474f51eb4ac24c19c8581c8c9c4de470
 *  9239857d21c910707c8daa797300490010ded474
 *  479e2a07c51b6b39c4574ebbc9a8cec9178a54ff
 *  de71ab0c744980007c1414de6f6119541fea6024
 *  c3ec336f90eb0744b6f1a854d5de74e74e318b08
 *  466376bc4eace4b9a3f01f852b2aab1e14b3a486
 *  f1165e812dfbc3fc1024c8c44cf7a6a9b7f2070c
 *  26412ec69f0fef6e2ab5058fde0a124f634028c8
 *  63e41eeec911df03909a3efed6584d18fa4646f8
 *
 *  cve/linux-4.12 commits:
 *  1ef139ed8f0b9507a25277dc460ad3f934f553a5
 *  a403fd08aeb9a35295956e0a641514df19c8d08d
 *  24c09bde977cac546ceae4c676ba23e58c984194
 *  2c9f94fe3973656e7d0f52ab046debba7ef09b58
 *  008726cf521df0fb29f80ab2a42f768a726c1623
 *  497557f3933d121af16854d6d9c77c60591e9f0f
 *  c8775513e0fde2a289e907fdc39524af2afcb13e
 *  033078a6c9e12b499e17f4f97d7501f9a9b336f6
 *  2bdfa858e87f669b91bb955f7f3b4fc5b159ddbc
 *  aaf4f1097d490e2739e14b667015b1950829a03c
 *  90ae3b8cac467d6f6e5c75c37d45602736642eed
 *  da16d0af3291c7dd6e6d378912fcdc7ec8d659d6
 *  4abed7e0eec06c12e9628c526d7d8fb35a9c6ea7
 *  3a4e6a4ed5d4f609e12f27443aefd9afcbe711c0
 *  c64904e69d419d89a0177d28131fcb0c800924e9
 *  f01634bac24f633bf393107e9d677321c9ed7014
 *  bd2c4f70ff87bdb70f3cb478125acd07068953c4
 *
 *  Intermediate SLE12-SP3 commits from embargo period:
 *  4865f6f18a1aa1c4b838040fab8855bce3efae59
 *  f4e1cb94cf231f225e0f59c496e113d5e62fccd3
 *  70fa18384eaf4e92de05d23a7414c8d3a91ec2b7
 *  ed2ab6d530c55f4727ac5707bdd091b8f81bb5a0
 *  8b38480146d6e3b30d850c8a8bfe81ffdfc8abc8
 *  fa90b469eb6494167415810a912a2e70fa080e20
 *  b98a0801ec1fee6544ef2c46ce117026ec39483f
 *  aa9692b71f3730c6f999b6f6b79fbf1a626a3850
 *  4383edfe889c11ddfb169d6a9d6c0493a9288bb6
 *  620e7bfe722aeb3a59479227ee3da15408668c78
 *  fd1ca80e5ccd9ab3c9d2f5974ae6f91070ca58f0
 *  69570cacfffeaa34f60b7f6b8141eb9f65c4aad6
 *  c7d7ce7ae5e0d5d1390b38b9eb1afec32b05577f
 *  030b5115ff3a6e885b31b13585fd745aba55fb47
 *
 *  SLE12-SP5 + SLE15-SP1 prerequisite commits indepedently backported
 *  before:
 *  f1cbca063f8ff55715d77ab68e415aec298781f5
 *  d120cea5703068af275e1e0bf6c73720ac3878db
 *  b6ec9c904f56728ed5ca49323767631cf48a6ff1
 *  c26cba48e8677cad948b9fa547bd1c820c58ed64
 *
 *  Intermediate SLE12-SP5 commits from embargo period:
 *  dee41915b6f3f072e8cb8612eb45c492bdbcbcc8
 *  90e36c35996c779b3c619b61bcd619695bc2a153
 *  ecdeb769852172a2c51fd6c15f4f07f45267d2d6
 *  5c7aeef091ef080d40385484aca5606488b8ae6f
 *  68ae9b5bed00c6d21f9a178adbddde13d829852d
 *  eee83b5a8b738cbbb1bb77935bdfc7d8f90875b8
 *  c6d1efbd2dcb2b1838415df331adc946d4c22d50
 *  7e2a0e96196292f14788186e676a6f36f013b629
 *  653451d4ca8c1640f8f58c2d0fd1604e80ead2e3
 *  f21ec06c55a0b391321f402ea1fa9442403ab6c4
 *  f4e587a2743d29b431d4e5a1a68ffebf7ffbbef2
 *  af0d6049fe64ffb47b0863b3d3ec168b4982fa92
 *
 *  Intermediate SLE15-SP1 commits from embargo period:
 *  c09b561a853a589b9b17930b77673601377f9fd7
 *  c6e33a6e1a6562af763b4da7b5442b42197d0a91
 *  8aa8854771758de8fee8a0a18a1957f7d0ae7d24
 *  a07d75fc7aa574d8098f9d1e63addfb2a54774ff
 *  47c26d1e3fa84319de36b34804e7159ef53b7f78
 *  3bfc90edc4d827c16aa0968e6a65ec9177133fe7
 *  8a18911a5d3190b87322f89cbf4c38efce169138
 *  dd274c98d3c70ea0e617ade36bd5a4796cf7ccec
 *  204c1057d5f44dfedaa51db9032d62b8b760a236
 *  ff3c96836706dc667a094a0a88cad8fc373a8a5e
 *  b4bebb6f26eb43ddd70dfadf66da77b9620f02a8
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

#if IS_ENABLED(CONFIG_DRM_I915)

#if !IS_MODULE(CONFIG_DRM_I915)
#error "Live patch supports only CONFIG_DRM_I915=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1173663.h"
#include "../kallsyms_relocs.h"
#include "bsc1173663_common.h"

#define LIVEPATCHED_MODULE "i915"

__printf(2, 3)
void (*klpe_drm_dbg)(unsigned int category, const char *format, ...);

struct i915_params (*klpe_i915_modparams) __read_mostly;

int (*klpe___i915_vma_do_pin)(struct i915_vma *vma,
		      u64 size, u64 alignment, u64 flags);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_dbg", (void *)&klpe_drm_dbg, "drm" },
	{ "i915_modparams", (void *)&klpe_i915_modparams, "i915" },
	{ "__i915_vma_do_pin", (void *)&klpe___i915_vma_do_pin, "i915" },
};

static int klp_bsc1173663_resolve_kallsyms(void)
{
	int ret, r;

	/* Keep going, return the first error, if any. */
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	r = klp_bsc1173663_cmd_parser_resolve_kallsyms();
	ret = ret ? : r;

	r = klp_bsc1173663_gem_resolve_kallsyms();
	ret = ret ? : r;

	r = klp_bsc1173663_gem_execbuffer_resolve_kallsyms();
	ret = ret ? : r;

	return ret;
}

static int livepatch_bsc1173663_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = klp_bsc1173663_resolve_kallsyms();
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1173663_module_nb = {
	.notifier_call = livepatch_bsc1173663_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1173663_init(void)
{
	int ret;

	ret = klp_bsc1173663_cmd_parser_init();
	if (ret)
		return ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = klp_bsc1173663_resolve_kallsyms();
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1173663_module_nb);
out:
	mutex_unlock(&module_mutex);

	if (ret)
		klp_bsc1173663_cmd_parser_cleanup();

	return ret;
}

void livepatch_bsc1173663_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1173663_module_nb);
	klp_bsc1173663_cmd_parser_cleanup();
}

#endif /* IS_ENABLED(CONFIG_DRM_I915) */
