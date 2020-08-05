/*
 * bsc1173663_common.h
 *
 * Fix for CVE-2019-0155, bsc#1173663 (common definitions/declarations)
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

#ifndef _BSC1173663_COMMON_H
#define _BSC1173663_COMMON_H

#include <drm/i915_drm.h>
#include <uapi/drm/i915_drm.h>
#include <uapi/drm/drm_fourcc.h>
#include <linux/io-mapping.h>
#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>
#include <linux/backlight.h>
#include <linux/hash.h>
#include <linux/kref.h>
#include <linux/perf_event.h>
#include <linux/pm_qos.h>
#include <linux/reservation.h>
#include <drm/drmP.h>
#include <drm/intel-gtt.h>
#include <drm/drm_gem.h>
#include <drm/drm_auth.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/list.h>
#include <linux/seqlock.h>
#include <linux/types.h>
#include <linux/hrtimer.h>
#include <linux/perf_event.h>
#include <linux/spinlock_types.h>
#include <drm/i915_drm.h>
#include <linux/dma-fence.h>
#include <linux/bug.h>
#include <linux/interrupt.h>
#include <linux/gfp.h>
#include <linux/kref.h>
#include <linux/notifier.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/radix-tree.h>
#include <linux/workqueue.h>
#include <linux/pci.h>
#include <linux/io-mapping.h>
#include <linux/rbtree.h>
#include <drm/drm_mm.h>
#include <linux/reservation.h>
#include <drm/drm_vma_manager.h>
#include <linux/io-mapping.h>
#include <linux/mm.h>
#include <linux/pagevec.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <drm/drm_mm.h>
#include <linux/stringify.h>
#include <linux/hdmi.h>
#include <drm/drm_crtc.h>
#include <drm/drm_rect.h>
#include <drm/drm_atomic.h>
#include <linux/sync_file.h>
#include <drm/drm_syncobj.h>
#include <linux/tracepoint.h>
#include <linux/hashtable.h>

/* klp-ccp: from include/drm/drm_print.h */
extern __printf(2, 3)
void (*klpe_drm_dbg)(unsigned int category, const char *format, ...);

#define KLPR_DRM_DEBUG(fmt, ...)						\
	(*klpe_drm_dbg)(DRM_UT_CORE, fmt, ##__VA_ARGS__)

#define KLPR_DRM_DEBUG_DRIVER(fmt, ...)					\
	(*klpe_drm_dbg)(DRM_UT_DRIVER, fmt, ##__VA_ARGS__)

/* klp-ccp: from drivers/gpu/drm/i915/i915_params.h */
#define I915_PARAMS_FOR_EACH(param) \
	param(char *, vbt_firmware, NULL) \
	param(int, modeset, -1) \
	param(int, lvds_channel_mode, 0) \
	param(int, panel_use_ssc, -1) \
	param(int, vbt_sdvo_panel_type, -1) \
	param(int, enable_dc, -1) \
	param(int, enable_fbc, -1) \
	param(int, enable_ppgtt, -1) \
	param(int, enable_psr, -1) \
	param(int, disable_power_well, -1) \
	param(int, enable_ips, 1) \
	param(int, invert_brightness, 0) \
	param(int, enable_guc, 0) \
	param(int, guc_log_level, -1) \
	param(char *, guc_firmware_path, NULL) \
	param(char *, huc_firmware_path, NULL) \
	param(char *, dmc_firmware_path, NULL) \
	param(int, mmio_debug, 0) \
	param(int, edp_vswing, 0) \
	param(int, reset, 2) \
	param(unsigned int, inject_load_failure, 0) \
	/* leave bools at the end to not create holes */ \
	param(bool, alpha_support, IS_ENABLED(CONFIG_DRM_I915_ALPHA_SUPPORT)) \
	param(bool, enable_hangcheck, true) \
	param(bool, fastboot, false) \
	param(bool, prefault_disable, false) \
	param(bool, load_detect_test, false) \
	param(bool, force_reset_modeset_test, false) \
	param(bool, error_capture, true) \
	param(bool, disable_display, false) \
	param(bool, verbose_state_checks, true) \
	param(bool, nuclear_pageflip, false) \
	param(bool, enable_dp_mst, true) \
	param(bool, enable_dpcd_backlight, false) \
	param(bool, enable_gvt, false)

#define MEMBER(T, member, ...) T member;
struct i915_params {
	I915_PARAMS_FOR_EACH(MEMBER);
};

extern struct i915_params (*klpe_i915_modparams) __read_mostly;

/* klp-ccp: from drivers/gpu/drm/i915/i915_reg.h */
typedef struct {
	uint32_t reg;
} i915_reg_t;

#define _MMIO(r) ((const i915_reg_t){ .reg = (r) })

static inline uint32_t i915_mmio_reg_offset(i915_reg_t reg)
{
	return reg.reg;
}

#define VECS_HW		3

#define MAX_ENGINE_CLASS	4

#define MAX_ENGINE_INSTANCE    3

#define GEN7_LRA_LIMITS_REG_NUM	13

#define   GMBUS_NUM_PINS	13 /* including 0 */

#define GEN7_GT_SCRATCH_REG_NUM			8

#define GEN7_SO_WRITE_OFFSET(n)		_MMIO(0x5280 + (n) * 4)

/* klp-ccp: from drivers/gpu/drm/i915/i915_utils.h */
#define ptr_mask_bits(ptr, n) ({					\
	unsigned long __v = (unsigned long)(ptr);			\
	(typeof(ptr))(__v & -BIT(n));					\
})

#define ptr_unpack_bits(ptr, bits, n) ({				\
	unsigned long __v = (unsigned long)(ptr);			\
	*(bits) = __v & (BIT(n) - 1);					\
	(typeof(ptr))(__v & -BIT(n));					\
})

#define page_mask_bits(ptr) ptr_mask_bits(ptr, PAGE_SHIFT)

/* klp-ccp: from drivers/gpu/drm/i915/intel_bios.h */
enum intel_backlight_type {
	INTEL_BACKLIGHT_PMIC,
	INTEL_BACKLIGHT_LPSS,
	INTEL_BACKLIGHT_DISPLAY_DDI,
	INTEL_BACKLIGHT_DSI_DCS,
	INTEL_BACKLIGHT_PANEL_DRIVER_INTERFACE,
};

struct edp_power_seq {
	u16 t1_t3;
	u16 t8;
	u16 t9;
	u16 t10;
	u16 t11_t12;
} __packed;

enum mipi_seq {
	MIPI_SEQ_END = 0,
	MIPI_SEQ_DEASSERT_RESET,	/* Spec says MipiAssertResetPin */
	MIPI_SEQ_INIT_OTP,
	MIPI_SEQ_DISPLAY_ON,
	MIPI_SEQ_DISPLAY_OFF,
	MIPI_SEQ_ASSERT_RESET,		/* Spec says MipiDeassertResetPin */
	MIPI_SEQ_BACKLIGHT_ON,		/* sequence block v2+ */
	MIPI_SEQ_BACKLIGHT_OFF,		/* sequence block v2+ */
	MIPI_SEQ_TEAR_ON,		/* sequence block v2+ */
	MIPI_SEQ_TEAR_OFF,		/* sequence block v3+ */
	MIPI_SEQ_POWER_ON,		/* sequence block v3+ */
	MIPI_SEQ_POWER_OFF,		/* sequence block v3+ */
	MIPI_SEQ_MAX
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_display.h */
enum pipe {
	INVALID_PIPE = -1,

	PIPE_A = 0,
	PIPE_B,
	PIPE_C,
	_PIPE_EDP,

	I915_MAX_PIPES = _PIPE_EDP
};

enum transcoder {
	TRANSCODER_A = 0,
	TRANSCODER_B,
	TRANSCODER_C,
	TRANSCODER_EDP,
	TRANSCODER_DSI_A,
	TRANSCODER_DSI_C,

	I915_MAX_TRANSCODERS
};

enum i9xx_plane_id {
	PLANE_A,
	PLANE_B,
	PLANE_C,
};

enum plane_id {
	PLANE_PRIMARY,
	PLANE_SPRITE0,
	PLANE_SPRITE1,
	PLANE_SPRITE2,
	PLANE_CURSOR,

	I915_MAX_PLANES,
};

enum port {
	PORT_NONE = -1,

	PORT_A = 0,
	PORT_B,
	PORT_C,
	PORT_D,
	PORT_E,
	PORT_F,

	I915_MAX_PORTS
};

#define I915_NUM_PHYS_VLV 2

enum intel_display_power_domain {
	POWER_DOMAIN_PIPE_A,
	POWER_DOMAIN_PIPE_B,
	POWER_DOMAIN_PIPE_C,
	POWER_DOMAIN_PIPE_A_PANEL_FITTER,
	POWER_DOMAIN_PIPE_B_PANEL_FITTER,
	POWER_DOMAIN_PIPE_C_PANEL_FITTER,
	POWER_DOMAIN_TRANSCODER_A,
	POWER_DOMAIN_TRANSCODER_B,
	POWER_DOMAIN_TRANSCODER_C,
	POWER_DOMAIN_TRANSCODER_EDP,
	POWER_DOMAIN_TRANSCODER_DSI_A,
	POWER_DOMAIN_TRANSCODER_DSI_C,
	POWER_DOMAIN_PORT_DDI_A_LANES,
	POWER_DOMAIN_PORT_DDI_B_LANES,
	POWER_DOMAIN_PORT_DDI_C_LANES,
	POWER_DOMAIN_PORT_DDI_D_LANES,
	POWER_DOMAIN_PORT_DDI_E_LANES,
	POWER_DOMAIN_PORT_DDI_F_LANES,
	POWER_DOMAIN_PORT_DDI_A_IO,
	POWER_DOMAIN_PORT_DDI_B_IO,
	POWER_DOMAIN_PORT_DDI_C_IO,
	POWER_DOMAIN_PORT_DDI_D_IO,
	POWER_DOMAIN_PORT_DDI_E_IO,
	POWER_DOMAIN_PORT_DDI_F_IO,
	POWER_DOMAIN_PORT_DSI,
	POWER_DOMAIN_PORT_CRT,
	POWER_DOMAIN_PORT_OTHER,
	POWER_DOMAIN_VGA,
	POWER_DOMAIN_AUDIO,
	POWER_DOMAIN_PLLS,
	POWER_DOMAIN_AUX_A,
	POWER_DOMAIN_AUX_B,
	POWER_DOMAIN_AUX_C,
	POWER_DOMAIN_AUX_D,
	POWER_DOMAIN_AUX_E,
	POWER_DOMAIN_AUX_F,
	POWER_DOMAIN_AUX_IO_A,
	POWER_DOMAIN_AUX_TBT1,
	POWER_DOMAIN_AUX_TBT2,
	POWER_DOMAIN_AUX_TBT3,
	POWER_DOMAIN_AUX_TBT4,
	POWER_DOMAIN_GMBUS,
	POWER_DOMAIN_MODESET,
	POWER_DOMAIN_GT_IRQ,
	POWER_DOMAIN_INIT,

	POWER_DOMAIN_NUM,
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_device_info.h */
enum intel_platform {
	INTEL_PLATFORM_UNINITIALIZED = 0,
	/* gen2 */
	INTEL_I830,
	INTEL_I845G,
	INTEL_I85X,
	INTEL_I865G,
	/* gen3 */
	INTEL_I915G,
	INTEL_I915GM,
	INTEL_I945G,
	INTEL_I945GM,
	INTEL_G33,
	INTEL_PINEVIEW,
	/* gen4 */
	INTEL_I965G,
	INTEL_I965GM,
	INTEL_G45,
	INTEL_GM45,
	/* gen5 */
	INTEL_IRONLAKE,
	/* gen6 */
	INTEL_SANDYBRIDGE,
	/* gen7 */
	INTEL_IVYBRIDGE,
	INTEL_VALLEYVIEW,
	INTEL_HASWELL,
	/* gen8 */
	INTEL_BROADWELL,
	INTEL_CHERRYVIEW,
	/* gen9 */
	INTEL_SKYLAKE,
	INTEL_BROXTON,
	INTEL_KABYLAKE,
	INTEL_GEMINILAKE,
	INTEL_COFFEELAKE,
	/* gen10 */
	INTEL_CANNONLAKE,
	/* gen11 */
	INTEL_ICELAKE,
	INTEL_MAX_PLATFORMS
};

#define DEV_INFO_FOR_EACH_FLAG(func) \
	func(is_mobile); \
	func(is_lp); \
	func(is_alpha_support); \
	/* Keep has_* in alphabetical order */ \
	func(has_64bit_reloc); \
	func(has_aliasing_ppgtt); \
	func(has_csr); \
	func(has_ddi); \
	func(has_dp_mst); \
	func(has_reset_engine); \
	func(has_fbc); \
	func(has_fpga_dbg); \
	func(has_full_ppgtt); \
	func(has_full_48bit_ppgtt); \
	func(has_gmch_display); \
	func(has_guc); \
	func(has_guc_ct); \
	func(has_hotplug); \
	func(has_l3_dpf); \
	func(has_llc); \
	func(has_logical_ring_contexts); \
	func(has_logical_ring_elsq); \
	func(has_logical_ring_preemption); \
	func(has_overlay); \
	func(has_pooled_eu); \
	func(has_psr); \
	func(has_rc6); \
	func(has_rc6p); \
	func(has_resource_streamer); \
	func(has_runtime_pm); \
	func(has_snoop); \
	func(unfenced_needs_alignment); \
	func(cursor_needs_physical); \
	func(hws_needs_physical); \
	func(overlay_needs_physical); \
	func(supports_tv); \
	func(has_ipc);

#define GEN_MAX_SLICES		(6) /* CNL upper bound */
#define GEN_MAX_SUBSLICES	(8) /* ICL upper bound */

struct sseu_dev_info {
	u8 slice_mask;
	u8 subslice_mask[GEN_MAX_SUBSLICES];
	u16 eu_total;
	u8 eu_per_subslice;
	u8 min_eu_in_pool;
	/* For each slice, which subslice(s) has(have) 7 EUs (bitfield)? */
	u8 subslice_7eu[3];
	u8 has_slice_pg:1;
	u8 has_subslice_pg:1;
	u8 has_eu_pg:1;

	/* Topology fields */
	u8 max_slices;
	u8 max_subslices;
	u8 max_eus_per_subslice;

	/* We don't have more than 8 eus per subslice at the moment and as we
	 * store eus enabled using bits, no need to multiply by eus per
	 * subslice.
	 */
	u8 eu_mask[GEN_MAX_SLICES * GEN_MAX_SUBSLICES];
};

typedef u8 intel_ring_mask_t;

struct intel_device_info {
	u16 gen_mask;

	u8 gen;
	u8 gt; /* GT number, 0 if undefined */
	intel_ring_mask_t ring_mask; /* Rings supported by the HW */

	enum intel_platform platform;

	unsigned int page_sizes; /* page sizes supported by the HW */

	u32 display_mmio_offset;

	u8 num_pipes;

#define DEFINE_FLAG(name) u8 name:1
	DEV_INFO_FOR_EACH_FLAG(DEFINE_FLAG);
	u16 ddb_size; /* in blocks */

	/* Register offsets for the various display pipes and transcoders */
	int pipe_offsets[I915_MAX_TRANSCODERS];
	int trans_offsets[I915_MAX_TRANSCODERS];
	int palette_offsets[I915_MAX_PIPES];
	int cursor_offsets[I915_MAX_PIPES];

	struct color_luts {
		u16 degamma_lut_size;
		u16 gamma_lut_size;
	} color;
};

struct intel_runtime_info {
	/*
	 * Platform mask is used for optimizing or-ed IS_PLATFORM calls into
	 * into single runtime conditionals, and also to provide groundwork
	 * for future per platform, or per SKU build optimizations.
	 *
	 * Array can be extended when necessary if the corresponding
	 * BUILD_BUG_ON is hit.
	 */
	u32 platform_mask[2];

	u16 device_id;

	u8 num_sprites[I915_MAX_PIPES];
	u8 num_scalers[I915_MAX_PIPES];

	u8 num_rings;

	/* Slice/subslice/EU info */
	struct sseu_dev_info sseu;

	u32 cs_timestamp_frequency_khz;

	/* Enabled (not fused off) media engine bitmasks. */
	u8 vdbox_enable;
	u8 vebox_enable;
};

struct intel_driver_caps {
	unsigned int scheduler;
	bool has_logical_contexts:1;
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_dpll_mgr.h */
struct intel_crtc;
struct intel_crtc_state;
struct intel_encoder;

#define I915_NUM_PLLS 7

struct intel_dpll_hw_state {
	/* i9xx, pch plls */
	uint32_t dpll;
	uint32_t dpll_md;
	uint32_t fp0;
	uint32_t fp1;

	/* hsw, bdw */
	uint32_t wrpll;
	uint32_t spll;

	/* skl */
	/*
	 * DPLL_CTRL1 has 6 bits for each each this DPLL. We store those in
	 * lower part of ctrl1 and they get shifted into position when writing
	 * the register.  This allows us to easily compare the state to share
	 * the DPLL.
	 */
	uint32_t ctrl1;
	/* HDMI only, 0 when used for DP */
	uint32_t cfgcr1, cfgcr2;

	/* cnl */
	uint32_t cfgcr0;
	/* CNL also uses cfgcr1 */

	/* bxt */
	uint32_t ebb0, ebb4, pll0, pll1, pll2, pll3, pll6, pll8, pll9, pll10,
		 pcsdw12;

	/*
	 * ICL uses the following, already defined:
	 * uint32_t cfgcr0, cfgcr1;
	 */
	uint32_t mg_refclkin_ctl;
	uint32_t mg_clktop2_coreclkctl1;
	uint32_t mg_clktop2_hsclkctl;
	uint32_t mg_pll_div0;
	uint32_t mg_pll_div1;
	uint32_t mg_pll_lf;
	uint32_t mg_pll_frac_lock;
	uint32_t mg_pll_ssc;
	uint32_t mg_pll_bias;
	uint32_t mg_pll_tdc_coldst_bias;
	uint32_t mg_pll_bias_mask;
	uint32_t mg_pll_tdc_coldst_bias_mask;
};

struct intel_shared_dpll_state {
	/**
	 * @crtc_mask: mask of CRTC using this DPLL, active or not
	 */
	unsigned crtc_mask;

	/**
	 * @hw_state: hardware configuration for the DPLL stored in
	 * struct &intel_dpll_hw_state.
	 */
	struct intel_dpll_hw_state hw_state;
};

struct intel_shared_dpll {
	/**
	 * @state:
	 *
	 * Store the state for the pll, including the its hw state
	 * and CRTCs using it.
	 */
	struct intel_shared_dpll_state state;

	/**
	 * @active_mask: mask of active CRTCs (i.e. DPMS on) using this DPLL
	 */
	unsigned active_mask;

	/**
	 * @on: is the PLL actually active? Disabled during modeset
	 */
	bool on;

	/**
	 * @info: platform specific info
	 */
	const struct dpll_info *info;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_batch_pool.h */
struct i915_gem_batch_pool {
	struct intel_engine_cs *engine;
	struct list_head cache_list[4];
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_pmu.h */
enum {
	__I915_SAMPLE_FREQ_ACT = 0,
	__I915_SAMPLE_FREQ_REQ,
	__I915_SAMPLE_RC6,
	__I915_SAMPLE_RC6_ESTIMATED,
	__I915_NUM_PMU_SAMPLERS
};

#define I915_PMU_MASK_BITS \
	((1 << I915_PMU_SAMPLE_BITS) + \
	 (I915_PMU_LAST + 1 - __I915_PMU_OTHER(0)))

#define I915_ENGINE_SAMPLE_COUNT (I915_SAMPLE_SEMA + 1)

struct i915_pmu_sample {
	u64 cur;
};

struct i915_pmu {
	/**
	 * @node: List node for CPU hotplug handling.
	 */
	struct hlist_node node;
	/**
	 * @base: PMU base.
	 */
	struct pmu base;
	/**
	 * @lock: Lock protecting enable mask and ref count handling.
	 */
	spinlock_t lock;
	/**
	 * @timer: Timer for internal i915 PMU sampling.
	 */
	struct hrtimer timer;
	/**
	 * @enable: Bitmask of all currently enabled events.
	 *
	 * Bits are derived from uAPI event numbers in a way that low 16 bits
	 * correspond to engine event _sample_ _type_ (I915_SAMPLE_QUEUED is
	 * bit 0), and higher bits correspond to other events (for instance
	 * I915_PMU_ACTUAL_FREQUENCY is bit 16 etc).
	 *
	 * In other words, low 16 bits are not per engine but per engine
	 * sampler type, while the upper bits are directly mapped to other
	 * event types.
	 */
	u64 enable;

	/**
	 * @timer_last:
	 *
	 * Timestmap of the previous timer invocation.
	 */
	ktime_t timer_last;

	/**
	 * @enable_count: Reference counts for the enabled events.
	 *
	 * Array indices are mapped in the same way as bits in the @enable field
	 * and they are used to control sampling on/off when multiple clients
	 * are using the PMU API.
	 */
	unsigned int enable_count[I915_PMU_MASK_BITS];
	/**
	 * @timer_enabled: Should the internal sampling timer be running.
	 */
	bool timer_enabled;
	/**
	 * @sample: Current and previous (raw) counters for sampling events.
	 *
	 * These counters are updated from the i915 PMU sampling timer.
	 *
	 * Only global counters are held here, while the per-engine ones are in
	 * struct intel_engine_cs.
	 */
	struct i915_pmu_sample sample[__I915_NUM_PMU_SAMPLERS];
	/**
	 * @suspended_jiffies_last: Cached suspend time from PM core.
	 */
	unsigned long suspended_jiffies_last;
	/**
	 * @i915_attr: Memory block holding device attributes.
	 */
	void *i915_attr;
	/**
	 * @pmu_attr: Memory block holding device attributes.
	 */
	void *pmu_attr;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem.h */
#define GEM_BUG_ON(expr) BUILD_BUG_ON_INVALID(expr)

#define GEM_DEBUG_DECL(var)

#define I915_NUM_ENGINES 8

/* klp-ccp: from drivers/gpu/drm/i915/i915_scheduler.h */
struct i915_sched_attr {
	/**
	 * @priority: execution and service priority
	 *
	 * All clients are equal, but some are more equal than others!
	 *
	 * Requests from a context with a greater (more positive) value of
	 * @priority will be executed before those with a lower @priority
	 * value, forming a simple QoS.
	 *
	 * The &drm_i915_private.kernel_context is assigned the lowest priority.
	 */
	int priority;
};

struct i915_sched_node {
	struct list_head signalers_list; /* those before us, we depend upon */
	struct list_head waiters_list; /* those after us, they depend upon us */
	struct list_head link;
	struct i915_sched_attr attr;
};

struct i915_dependency {
	struct i915_sched_node *signaler;
	struct list_head signal_link;
	struct list_head wait_link;
	struct list_head dfs_link;
	unsigned long flags;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_sw_fence.h */
struct i915_sw_fence {
	wait_queue_head_t wait;
	unsigned long flags;
	atomic_t pending;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_request.h */
struct intel_wait {
	struct rb_node node;
	struct task_struct *tsk;
	struct i915_request *request;
	u32 seqno;
};

struct intel_signal_node {
	struct intel_wait wait;
	struct list_head link;
};

struct i915_capture_list {
	struct i915_capture_list *next;
	struct i915_vma *vma;
};

struct i915_request {
	struct dma_fence fence;
	spinlock_t lock;

	/** On Which ring this request was generated */
	struct drm_i915_private *i915;

	/**
	 * Context and ring buffer related to this request
	 * Contexts are refcounted, so when this request is associated with a
	 * context, we must increment the context's refcount, to guarantee that
	 * it persists while any request is linked to it. Requests themselves
	 * are also refcounted, so the request will only be freed when the last
	 * reference to it is dismissed, and the code in
	 * i915_request_free() will then decrement the refcount on the
	 * context.
	 */
	struct i915_gem_context *gem_context;
	struct intel_engine_cs *engine;
	struct intel_context *hw_context;
	struct intel_ring *ring;
	struct i915_timeline *timeline;
	struct intel_signal_node signaling;

	/*
	 * Fences for the various phases in the request's lifetime.
	 *
	 * The submit fence is used to await upon all of the request's
	 * dependencies. When it is signaled, the request is ready to run.
	 * It is used by the driver to then queue the request for execution.
	 */
	struct i915_sw_fence submit;
	wait_queue_entry_t submitq;
	wait_queue_head_t execute;

	/*
	 * A list of everyone we wait upon, and everyone who waits upon us.
	 * Even though we will not be submitted to the hardware before the
	 * submit fence is signaled (it waits for all external events as well
	 * as our own requests), the scheduler still needs to know the
	 * dependency tree for the lifetime of the request (from execbuf
	 * to retirement), i.e. bidirectional dependency information for the
	 * request not tied to individual fences.
	 */
	struct i915_sched_node sched;
	struct i915_dependency dep;

	/**
	 * GEM sequence number associated with this request on the
	 * global execution timeline. It is zero when the request is not
	 * on the HW queue (i.e. not on the engine timeline list).
	 * Its value is guarded by the timeline spinlock.
	 */
	u32 global_seqno;

	/** Position in the ring of the start of the request */
	u32 head;

	/** Position in the ring of the start of the user packets */
	u32 infix;

	/**
	 * Position in the ring of the start of the postfix.
	 * This is required to calculate the maximum available ring space
	 * without overwriting the postfix.
	 */
	u32 postfix;

	/** Position in the ring of the end of the whole request */
	u32 tail;

	/** Position in the ring of the end of any workarounds after the tail */
	u32 wa_tail;

	/** Preallocate space in the ring for the emitting the request */
	u32 reserved_space;

	/** Batch buffer related to this request if any (used for
	 * error state dump only).
	 */
	struct i915_vma *batch;
	/**
	 * Additional buffers requested by userspace to be captured upon
	 * a GPU hang. The vma/obj on this list are protected by their
	 * active reference - all objects on this list must also be
	 * on the active_list (of their final request).
	 */
	struct i915_capture_list *capture_list;
	struct list_head active_list;

	/** Time at which this request was emitted, in jiffies. */
	unsigned long emitted_jiffies;

	bool waitboost;

	/** engine->request_list entry for this request */
	struct list_head link;

	/** ring->request_list entry for this request */
	struct list_head ring_link;

	struct drm_i915_file_private *file_priv;
	/** file_priv list entry for this request */
	struct list_head client_link;
};

struct i915_gem_active;

typedef void (*i915_gem_retire_fn)(struct i915_gem_active *,
				   struct i915_request *);

struct i915_gem_active {
	struct i915_request __rcu *request;
	struct list_head link;
	i915_gem_retire_fn retire;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_selftest.h */
#define I915_SELFTEST_DECLARE(x)

/* klp-ccp: from drivers/gpu/drm/i915/i915_timeline.h */
struct i915_timeline {
	u64 fence_context;
	u32 seqno;

	spinlock_t lock;

	/**
	 * List of breadcrumbs associated with GPU requests currently
	 * outstanding.
	 */
	struct list_head requests;

	/* Contains an RCU guarded pointer to the last request. No reference is
	 * held to the request, users must carefully acquire a reference to
	 * the request using i915_gem_active_get_request_rcu(), or hold the
	 * struct_mutex.
	 */
	struct i915_gem_active last_request;

	/**
	 * We track the most recent seqno that we wait on in every context so
	 * that we only have to emit a new await and dependency on a more
	 * recent sync point. As the contexts may be executed out-of-order, we
	 * have to track each individually and can not rely on an absolute
	 * global_seqno. When we know that all tracked fences are completed
	 * (i.e. when the driver is idle), we know that the syncmap is
	 * redundant and we can discard it without loss of generality.
	 */
	struct i915_syncmap *sync;
	/**
	 * Separately to the inter-context seqno map above, we track the last
	 * barrier (e.g. semaphore wait) to the global engine timelines. Note
	 * that this tracks global_seqno rather than the context.seqno, and
	 * so it is subject to the limitations of hw wraparound and that we
	 * may need to revoke global_seqno (on pre-emption).
	 */
	u32 global_sync[I915_NUM_ENGINES];

	struct list_head link;
	const char *name;

	struct kref kref;
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_gpu_commands.h */
#define INSTR_CLIENT_SHIFT      29
#define   INSTR_MI_CLIENT       0x0
#define   INSTR_BC_CLIENT       0x2
#define   INSTR_RC_CLIENT       0x3

#define MI_INSTR(opcode, flags) (((opcode) << 23) | (flags))

#define MI_NOOP			MI_INSTR(0, 0)
#define MI_USER_INTERRUPT	MI_INSTR(0x02, 0)
#define MI_WAIT_FOR_EVENT       MI_INSTR(0x03, 0)

#define MI_FLUSH		MI_INSTR(0x04, 0)

#define MI_REPORT_HEAD		MI_INSTR(0x07, 0)
#define MI_ARB_ON_OFF		MI_INSTR(0x08, 0)

#define MI_BATCH_BUFFER_END	MI_INSTR(0x0a, 0)
#define MI_SUSPEND_FLUSH	MI_INSTR(0x0b, 0)

#define MI_LOAD_SCAN_LINES_INCL MI_INSTR(0x12, 0)

#define MI_STORE_DWORD_IMM	MI_INSTR(0x20, 1)
#define MI_STORE_DWORD_IMM_GEN4	MI_INSTR(0x20, 2)
#define   MI_MEM_VIRTUAL	(1 << 22) /* 945,g33,965 */
#define   MI_USE_GGTT		(1 << 22) /* g4x+ */

#define MI_LOAD_REGISTER_IMM(x)	MI_INSTR(0x22, 2*(x)-1)

#define MI_STORE_REGISTER_MEM_GEN8   MI_INSTR(0x24, 2)

#define MI_FLUSH_DW		MI_INSTR(0x26, 1) /* for GEN6 */

#define MI_LOAD_REGISTER_MEM	   MI_INSTR(0x29, 1)
#define MI_LOAD_REGISTER_MEM_GEN8  MI_INSTR(0x29, 2)

#define   MI_BATCH_PPGTT_HSW		(1<<8)

#define MI_BATCH_BUFFER_START	MI_INSTR(0x31, 0)
#define MI_BATCH_BUFFER_START_GEN8	MI_INSTR(0x31, 1)

#define MI_ARB_CHECK            MI_INSTR(0x05, 0)

#define MI_LOAD_SCAN_LINES_EXCL MI_INSTR(0x13, 0)

#define MI_UPDATE_GTT           MI_INSTR(0x23, 0)

#define MI_LOAD_REGISTER_REG    MI_INSTR(0x2A, 0)

/* klp-ccp: from drivers/gpu/drm/i915/intel_workarounds.h */
struct i915_wa_list {
	const char	*name;
	struct i915_wa	*list;
	unsigned int	count;
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_ringbuffer.h */
#define I915_CMD_HASH_ORDER 9

struct intel_hw_status_page {
	struct i915_vma *vma;
	u32 *page_addr;
	u32 ggtt_offset;
};

enum intel_engine_hangcheck_action {
	ENGINE_IDLE = 0,
	ENGINE_WAIT,
	ENGINE_ACTIVE_SEQNO,
	ENGINE_ACTIVE_HEAD,
	ENGINE_ACTIVE_SUBUNITS,
	ENGINE_WAIT_KICK,
	ENGINE_DEAD,
};

#define I915_MAX_SLICES	3
#define I915_MAX_SUBSLICES 8

struct intel_instdone {
	u32 instdone;
	/* The following exist only in the RCS engine */
	u32 slice_common;
	u32 sampler[I915_MAX_SLICES][I915_MAX_SUBSLICES];
	u32 row[I915_MAX_SLICES][I915_MAX_SUBSLICES];
};

struct intel_engine_hangcheck {
	u64 acthd;
	u32 seqno;
	enum intel_engine_hangcheck_action action;
	unsigned long action_timestamp;
	int deadlock;
	struct intel_instdone instdone;
	struct i915_request *active_request;
	bool stalled:1;
	bool wedged:1;
};

struct intel_ring {
	struct i915_vma *vma;
	void *vaddr;

	struct i915_timeline *timeline;
	struct list_head request_list;
	struct list_head active_link;

	u32 head;
	u32 tail;
	u32 emit;

	u32 space;
	u32 size;
	u32 effective_size;
};

struct i915_ctx_workarounds {
	struct i915_wa_ctx_bb {
		u32 offset;
		u32 size;
	} indirect_ctx, per_ctx;
	struct i915_vma *vma;
};

enum intel_engine_id {
	RCS = 0,
	BCS,
	VCS,
	VCS2,
	VCS3,
	VCS4,
#define _VCS(n) (VCS + (n))
	VECS,
	VECS2
};

struct i915_priolist {
	struct rb_node node;
	struct list_head requests;
	int priority;
};

struct intel_engine_execlists {
	/**
	 * @tasklet: softirq tasklet for bottom handler
	 */
	struct tasklet_struct tasklet;

	/**
	 * @default_priolist: priority list for I915_PRIORITY_NORMAL
	 */
	struct i915_priolist default_priolist;

	/**
	 * @no_priolist: priority lists disabled
	 */
	bool no_priolist;

	/**
	 * @submit_reg: gen-specific execlist submission register
	 * set to the ExecList Submission Port (elsp) register pre-Gen11 and to
	 * the ExecList Submission Queue Contents register array for Gen11+
	 */
	u32 __iomem *submit_reg;

	/**
	 * @ctrl_reg: the enhanced execlists control register, used to load the
	 * submit queue on the HW and to request preemptions to idle
	 */
	u32 __iomem *ctrl_reg;

	/**
	 * @port: execlist port states
	 *
	 * For each hardware ELSP (ExecList Submission Port) we keep
	 * track of the last request and the number of times we submitted
	 * that port to hw. We then count the number of times the hw reports
	 * a context completion or preemption. As only one context can
	 * be active on hw, we limit resubmission of context to port[0]. This
	 * is called Lite Restore, of the context.
	 */
	struct execlist_port {
		/**
		 * @request_count: combined request and submission count
		 */
		struct i915_request *request_count;

		/**
		 * @context_id: context ID for port
		 */
		GEM_DEBUG_DECL(u32 context_id);

#define EXECLIST_MAX_PORTS 2
	} port[EXECLIST_MAX_PORTS];

	/**
	 * @active: is the HW active? We consider the HW as active after
	 * submitting any context for execution and until we have seen the
	 * last context completion event. After that, we do not expect any
	 * more events until we submit, and so can park the HW.
	 *
	 * As we have a small number of different sources from which we feed
	 * the HW, we track the state of each inside a single bitfield.
	 */
	unsigned int active;

	/**
	 * @port_mask: number of execlist ports - 1
	 */
	unsigned int port_mask;

	/**
	 * @queue_priority: Highest pending priority.
	 *
	 * When we add requests into the queue, or adjust the priority of
	 * executing requests, we compute the maximum priority of those
	 * pending requests. We can then use this value to determine if
	 * we need to preempt the executing requests to service the queue.
	 */
	int queue_priority;

	/**
	 * @queue: queue of requests, in priority lists
	 */
	struct rb_root_cached queue;

	/**
	 * @csb_write: control register for Context Switch buffer
	 *
	 * Note this register may be either mmio or HWSP shadow.
	 */
	u32 *csb_write;

	/**
	 * @csb_status: status array for Context Switch buffer
	 *
	 * Note these register may be either mmio or HWSP shadow.
	 */
	u32 *csb_status;

	/**
	 * @preempt_complete_status: expected CSB upon completing preemption
	 */
	u32 preempt_complete_status;

	/**
	 * @csb_head: context status buffer head
	 */
	u8 csb_head;

	I915_SELFTEST_DECLARE(struct st_preempt_hang preempt_hang;)
};

#define INTEL_ENGINE_CS_MAX_NAME 8

struct intel_engine_cs {
	struct drm_i915_private *i915;
	char name[INTEL_ENGINE_CS_MAX_NAME];

	enum intel_engine_id id;
	unsigned int hw_id;
	unsigned int guc_id;

	u8 uabi_id;
	u8 uabi_class;

	u8 class;
	u8 instance;
	u32 context_size;
	u32 mmio_base;

	struct intel_ring *buffer;

	struct i915_timeline timeline;

	struct drm_i915_gem_object *default_state;
	void *pinned_default_state;

	unsigned long irq_posted;

	/* Rather than have every client wait upon all user interrupts,
	 * with the herd waking after every interrupt and each doing the
	 * heavyweight seqno dance, we delegate the task (of being the
	 * bottom-half of the user interrupt) to the first client. After
	 * every interrupt, we wake up one client, who does the heavyweight
	 * coherent seqno read and either goes back to sleep (if incomplete),
	 * or wakes up all the completed clients in parallel, before then
	 * transferring the bottom-half status to the next client in the queue.
	 *
	 * Compared to walking the entire list of waiters in a single dedicated
	 * bottom-half, we reduce the latency of the first waiter by avoiding
	 * a context switch, but incur additional coherent seqno reads when
	 * following the chain of request breadcrumbs. Since it is most likely
	 * that we have a single client waiting on each seqno, then reducing
	 * the overhead of waking that client is much preferred.
	 */
	struct intel_breadcrumbs {
		spinlock_t irq_lock; /* protects irq_*; irqsafe */
		struct intel_wait *irq_wait; /* oldest waiter by retirement */

		spinlock_t rb_lock; /* protects the rb and wraps irq_lock */
		struct rb_root waiters; /* sorted by retirement, priority */
		struct list_head signals; /* sorted by retirement */
		struct task_struct *signaler; /* used for fence signalling */

		struct timer_list fake_irq; /* used after a missed interrupt */
		struct timer_list hangcheck; /* detect missed interrupts */

		unsigned int hangcheck_interrupts;
		unsigned int irq_enabled;
		unsigned int irq_count;

		bool irq_armed : 1;
		I915_SELFTEST_DECLARE(bool mock : 1);
	} breadcrumbs;

	struct {
		/**
		 * @enable: Bitmask of enable sample events on this engine.
		 *
		 * Bits correspond to sample event types, for instance
		 * I915_SAMPLE_QUEUED is bit 0 etc.
		 */
		u32 enable;
		/**
		 * @enable_count: Reference count for the enabled samplers.
		 *
		 * Index number corresponds to @enum drm_i915_pmu_engine_sample.
		 */
		unsigned int enable_count[I915_ENGINE_SAMPLE_COUNT];
		/**
		 * @sample: Counter values for sampling events.
		 *
		 * Our internal timer stores the current counters in this field.
		 *
		 * Index number corresponds to @enum drm_i915_pmu_engine_sample.
		 */
		struct i915_pmu_sample sample[I915_ENGINE_SAMPLE_COUNT];
	} pmu;

	/*
	 * A pool of objects to use as shadow copies of client batch buffers
	 * when the command parser is enabled. Prevents the client from
	 * modifying the batch contents after software parsing.
	 */
	struct i915_gem_batch_pool batch_pool;

	struct intel_hw_status_page status_page;
	struct i915_ctx_workarounds wa_ctx;
	struct i915_wa_list wa_list;
	struct i915_vma *scratch;

	u32             irq_keep_mask; /* always keep these interrupts */
	u32		irq_enable_mask; /* bitmask to enable ring interrupt */
	void		(*irq_enable)(struct intel_engine_cs *engine);
	void		(*irq_disable)(struct intel_engine_cs *engine);

	int		(*init_hw)(struct intel_engine_cs *engine);

	struct {
		struct i915_request *(*prepare)(struct intel_engine_cs *engine);
		void (*reset)(struct intel_engine_cs *engine,
			      struct i915_request *rq);
		void (*finish)(struct intel_engine_cs *engine);
	} reset;

	void		(*park)(struct intel_engine_cs *engine);
	void		(*unpark)(struct intel_engine_cs *engine);

	void		(*set_default_submission)(struct intel_engine_cs *engine);

	struct intel_context *(*context_pin)(struct intel_engine_cs *engine,
					     struct i915_gem_context *ctx);

	int		(*request_alloc)(struct i915_request *rq);
	int		(*init_context)(struct i915_request *rq);

	int		(*emit_flush)(struct i915_request *request, u32 mode);
	int		(*emit_bb_start)(struct i915_request *rq,
					 u64 offset, u32 length,
					 unsigned int dispatch_flags);
#define I915_DISPATCH_SECURE BIT(0)
#define I915_DISPATCH_PINNED BIT(1)
#define I915_DISPATCH_RS     BIT(2)
	void		(*emit_breadcrumb)(struct i915_request *rq, u32 *cs);
	int		emit_breadcrumb_sz;

	/* Pass the request to the hardware queue (e.g. directly into
	 * the legacy ringbuffer or to the end of an execlist).
	 *
	 * This is called from an atomic context with irqs disabled; must
	 * be irq safe.
	 */
	void		(*submit_request)(struct i915_request *rq);

	/* Call when the priority on a request has changed and it and its
	 * dependencies may need rescheduling. Note the request itself may
	 * not be ready to run!
	 *
	 * Called under the struct_mutex.
	 */
	void		(*schedule)(struct i915_request *request,
				    const struct i915_sched_attr *attr);

	/*
	 * Cancel all requests on the hardware, or queued for execution.
	 * This should only cancel the ready requests that have been
	 * submitted to the engine (via the engine->submit_request callback).
	 * This is called when marking the device as wedged.
	 */
	void		(*cancel_requests)(struct intel_engine_cs *engine);

	/* Some chipsets are not quite as coherent as advertised and need
	 * an expensive kick to force a true read of the up-to-date seqno.
	 * However, the up-to-date seqno is not always required and the last
	 * seen value is good enough. Note that the seqno will always be
	 * monotonic, even if not coherent.
	 */
	void		(*irq_seqno_barrier)(struct intel_engine_cs *engine);
	void		(*cleanup)(struct intel_engine_cs *engine);

	/* GEN8 signal/wait table - never trust comments!
	 *	  signal to	signal to    signal to   signal to      signal to
	 *	    RCS		   VCS          BCS        VECS		 VCS2
	 *      --------------------------------------------------------------------
	 *  RCS | NOP (0x00) | VCS (0x08) | BCS (0x10) | VECS (0x18) | VCS2 (0x20) |
	 *	|-------------------------------------------------------------------
	 *  VCS | RCS (0x28) | NOP (0x30) | BCS (0x38) | VECS (0x40) | VCS2 (0x48) |
	 *	|-------------------------------------------------------------------
	 *  BCS | RCS (0x50) | VCS (0x58) | NOP (0x60) | VECS (0x68) | VCS2 (0x70) |
	 *	|-------------------------------------------------------------------
	 * VECS | RCS (0x78) | VCS (0x80) | BCS (0x88) |  NOP (0x90) | VCS2 (0x98) |
	 *	|-------------------------------------------------------------------
	 * VCS2 | RCS (0xa0) | VCS (0xa8) | BCS (0xb0) | VECS (0xb8) | NOP  (0xc0) |
	 *	|-------------------------------------------------------------------
	 *
	 * Generalization:
	 *  f(x, y) := (x->id * NUM_RINGS * seqno_size) + (seqno_size * y->id)
	 *  ie. transpose of g(x, y)
	 *
	 *	 sync from	sync from    sync from    sync from	sync from
	 *	    RCS		   VCS          BCS        VECS		 VCS2
	 *      --------------------------------------------------------------------
	 *  RCS | NOP (0x00) | VCS (0x28) | BCS (0x50) | VECS (0x78) | VCS2 (0xa0) |
	 *	|-------------------------------------------------------------------
	 *  VCS | RCS (0x08) | NOP (0x30) | BCS (0x58) | VECS (0x80) | VCS2 (0xa8) |
	 *	|-------------------------------------------------------------------
	 *  BCS | RCS (0x10) | VCS (0x38) | NOP (0x60) | VECS (0x88) | VCS2 (0xb0) |
	 *	|-------------------------------------------------------------------
	 * VECS | RCS (0x18) | VCS (0x40) | BCS (0x68) |  NOP (0x90) | VCS2 (0xb8) |
	 *	|-------------------------------------------------------------------
	 * VCS2 | RCS (0x20) | VCS (0x48) | BCS (0x70) | VECS (0x98) |  NOP (0xc0) |
	 *	|-------------------------------------------------------------------
	 *
	 * Generalization:
	 *  g(x, y) := (y->id * NUM_RINGS * seqno_size) + (seqno_size * x->id)
	 *  ie. transpose of f(x, y)
	 */
	struct {
#define GEN6_SEMAPHORE_LAST	VECS_HW
#define GEN6_NUM_SEMAPHORES	(GEN6_SEMAPHORE_LAST + 1)
		struct {
			/* our mbox written by others */
			u32		wait[GEN6_NUM_SEMAPHORES];
			/* mboxes this ring signals to */
			i915_reg_t	signal[GEN6_NUM_SEMAPHORES];
		} mbox;

		/* AKA wait() */
		int	(*sync_to)(struct i915_request *rq,
				   struct i915_request *signal);
		u32	*(*signal)(struct i915_request *rq, u32 *cs);
	} semaphore;

	struct intel_engine_execlists execlists;

	/* Contexts are pinned whilst they are active on the GPU. The last
	 * context executed remains active whilst the GPU is idle - the
	 * switch away and write to the context object only occurs on the
	 * next execution.  Contexts are only unpinned on retirement of the
	 * following request ensuring that we can always write to the object
	 * on the context switch even after idling. Across suspend, we switch
	 * to the kernel context and trash it as the save may not happen
	 * before the hardware is powered down.
	 */
	struct intel_context *last_retired_context;

	/* status_notifier: list of callbacks for context-switch changes */
	struct atomic_notifier_head context_status_notifier;

	struct intel_engine_hangcheck hangcheck;

#define I915_ENGINE_NEEDS_CMD_PARSER BIT(0)
	unsigned int flags;

	/*
	 * Table of commands the command parser needs to know about
	 * for this engine.
	 */
	DECLARE_HASHTABLE(cmd_hash, I915_CMD_HASH_ORDER);

	/*
	 * Table of registers allowed in commands that read/write registers.
	 */
	const struct drm_i915_reg_table *reg_tables;
	int reg_table_count;

	/*
	 * Returns the bitmask for the length field of the specified command.
	 * Return 0 for an unrecognized/invalid command.
	 *
	 * If the command parser finds an entry for a command in the engine's
	 * cmd_tables, it gets the command's length based on the table entry.
	 * If not, it calls this function to determine the per-engine length
	 * field encoding for the command (i.e. different opcode ranges use
	 * certain bits to encode the command length in the header).
	 */
	u32 (*get_cmd_length_mask)(u32 cmd_header);

	struct {
		/**
		 * @lock: Lock protecting the below fields.
		 */
		seqlock_t lock;
		/**
		 * @enabled: Reference count indicating number of listeners.
		 */
		unsigned int enabled;
		/**
		 * @active: Number of contexts currently scheduled in.
		 */
		unsigned int active;
		/**
		 * @enabled_at: Timestamp when busy stats were enabled.
		 */
		ktime_t enabled_at;
		/**
		 * @start: Timestamp of the last idle to active transition.
		 *
		 * Idle is defined as active == 0, active is active > 0.
		 */
		ktime_t start;
		/**
		 * @total: Total time this engine was busy.
		 *
		 * Accumulated time not counting the most recent block in cases
		 * where engine is currently busy (active > 0).
		 */
		ktime_t total;
	} stats;
};

static inline bool
intel_engine_needs_cmd_parser(const struct intel_engine_cs *engine)
{
	return engine->flags & I915_ENGINE_NEEDS_CMD_PARSER;
}

static inline void intel_ring_advance(struct i915_request *rq, u32 *cs)
{
	/* Dummy function.
	 *
	 * This serves as a placeholder in the code so that the reader
	 * can compare against the preceding intel_ring_begin() and
	 * check that the number of dwords emitted matches the space
	 * reserved for the command packet (i.e. the value passed to
	 * intel_ring_begin()).
	 */
	GEM_BUG_ON((rq->ring->vaddr + rq->ring->emit) != cs);
}

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_context.h */
struct i915_gem_context {
	/** i915: i915 device backpointer */
	struct drm_i915_private *i915;

	/** file_priv: owning file descriptor */
	struct drm_i915_file_private *file_priv;

	/**
	 * @ppgtt: unique address space (GTT)
	 *
	 * In full-ppgtt mode, each context has its own address space ensuring
	 * complete seperation of one client from all others.
	 *
	 * In other modes, this is a NULL pointer with the expectation that
	 * the caller uses the shared global GTT.
	 */
	struct i915_hw_ppgtt *ppgtt;

	/**
	 * @pid: process id of creator
	 *
	 * Note that who created the context may not be the principle user,
	 * as the context may be shared across a local socket. However,
	 * that should only affect the default context, all contexts created
	 * explicitly by the client are expected to be isolated.
	 */
	struct pid *pid;

	/**
	 * @name: arbitrary name
	 *
	 * A name is constructed for the context from the creator's process
	 * name, pid and user handle in order to uniquely identify the
	 * context in messages.
	 */
	const char *name;

	/** link: place with &drm_i915_private.context_list */
	struct list_head link;
	struct llist_node free_link;

	/**
	 * @ref: reference count
	 *
	 * A reference to a context is held by both the client who created it
	 * and on each request submitted to the hardware using the request
	 * (to ensure the hardware has access to the state until it has
	 * finished all pending writes). See i915_gem_context_get() and
	 * i915_gem_context_put() for access.
	 */
	struct kref ref;

	/**
	 * @rcu: rcu_head for deferred freeing.
	 */
	struct rcu_head rcu;

	/**
	 * @flags: small set of booleans
	 */
	unsigned long flags;
#define CONTEXT_NO_ZEROMAP		BIT(0)
	unsigned int hw_id;
	atomic_t hw_id_pin_count;
	struct list_head hw_id_link;

	/**
	 * @user_handle: userspace identifier
	 *
	 * A unique per-file identifier is generated from
	 * &drm_i915_file_private.contexts.
	 */
	u32 user_handle;

	struct i915_sched_attr sched;

	/** ggtt_offset_bias: placement restriction for context objects */
	u32 ggtt_offset_bias;

	/** engine: per-engine logical HW state */
	struct intel_context {
		struct i915_gem_context *gem_context;
		struct i915_vma *state;
		struct intel_ring *ring;
		u32 *lrc_reg_state;
		u64 lrc_desc;
		int pin_count;

		const struct intel_context_ops *ops;
	} __engine[I915_NUM_ENGINES];

	/** ring_size: size for allocating the per-engine ring buffer */
	u32 ring_size;
	/** desc_template: invariant fields for the HW context descriptor */
	u32 desc_template;

	/** guilty_count: How many times this context has caused a GPU hang. */
	atomic_t guilty_count;
	/**
	 * @active_count: How many times this context was active during a GPU
	 * hang, but did not cause it.
	 */
	atomic_t active_count;

	/** ban_score: Accumulated score of all hangs caused by this context. */
	atomic_t ban_score;

	/** remap_slice: Bitmask of cache lines that need remapping */
	u8 remap_slice;

	/** handles_vma: rbtree to look up our context specific obj/vma for
	 * the user handle. (user handles are per fd, but the binding is
	 * per vm, which may be one per context or shared with the global GTT)
	 */
	struct radix_tree_root handles_vma;

	/** handles_list: reverse list of all the rbtree entries in use for
	 * this context, which allows us to free all the allocations on
	 * context close.
	 */
	struct list_head handles_list;
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_opregion.h */
struct intel_opregion {
	struct opregion_header *header;
	struct opregion_acpi *acpi;
	struct opregion_swsci *swsci;
	u32 swsci_gbda_sub_functions;
	u32 swsci_sbcb_sub_functions;
	struct opregion_asle *asle;
	void *rvda;
	void *vbt_firmware;
	const void *vbt;
	u32 vbt_size;
	u32 *lid_state;
	struct work_struct asle_work;
	struct notifier_block acpi_notifier;
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_uncore.h */
enum forcewake_domain_id {
	FW_DOMAIN_ID_RENDER = 0,
	FW_DOMAIN_ID_BLITTER,
	FW_DOMAIN_ID_MEDIA,
	FW_DOMAIN_ID_MEDIA_VDBOX0,
	FW_DOMAIN_ID_MEDIA_VDBOX1,
	FW_DOMAIN_ID_MEDIA_VDBOX2,
	FW_DOMAIN_ID_MEDIA_VDBOX3,
	FW_DOMAIN_ID_MEDIA_VEBOX0,
	FW_DOMAIN_ID_MEDIA_VEBOX1,

	FW_DOMAIN_ID_COUNT
};

enum forcewake_domains {
	FORCEWAKE_RENDER	= BIT(FW_DOMAIN_ID_RENDER),
	FORCEWAKE_BLITTER	= BIT(FW_DOMAIN_ID_BLITTER),
	FORCEWAKE_MEDIA		= BIT(FW_DOMAIN_ID_MEDIA),
	FORCEWAKE_MEDIA_VDBOX0	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX0),
	FORCEWAKE_MEDIA_VDBOX1	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX1),
	FORCEWAKE_MEDIA_VDBOX2	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX2),
	FORCEWAKE_MEDIA_VDBOX3	= BIT(FW_DOMAIN_ID_MEDIA_VDBOX3),
	FORCEWAKE_MEDIA_VEBOX0	= BIT(FW_DOMAIN_ID_MEDIA_VEBOX0),
	FORCEWAKE_MEDIA_VEBOX1	= BIT(FW_DOMAIN_ID_MEDIA_VEBOX1),

	FORCEWAKE_ALL = BIT(FW_DOMAIN_ID_COUNT) - 1
};

struct intel_uncore_funcs {
	void (*force_wake_get)(struct drm_i915_private *dev_priv,
			       enum forcewake_domains domains);
	void (*force_wake_put)(struct drm_i915_private *dev_priv,
			       enum forcewake_domains domains);

	u8 (*mmio_readb)(struct drm_i915_private *dev_priv,
			 i915_reg_t r, bool trace);
	u16 (*mmio_readw)(struct drm_i915_private *dev_priv,
			  i915_reg_t r, bool trace);
	u32 (*mmio_readl)(struct drm_i915_private *dev_priv,
			  i915_reg_t r, bool trace);
	u64 (*mmio_readq)(struct drm_i915_private *dev_priv,
			  i915_reg_t r, bool trace);

	void (*mmio_writeb)(struct drm_i915_private *dev_priv,
			    i915_reg_t r, u8 val, bool trace);
	void (*mmio_writew)(struct drm_i915_private *dev_priv,
			    i915_reg_t r, u16 val, bool trace);
	void (*mmio_writel)(struct drm_i915_private *dev_priv,
			    i915_reg_t r, u32 val, bool trace);
};

struct intel_uncore {
	spinlock_t lock; /** lock is also taken in irq contexts. */

	const struct intel_forcewake_range *fw_domains_table;
	unsigned int fw_domains_table_entries;

	struct notifier_block pmic_bus_access_nb;
	struct intel_uncore_funcs funcs;

	unsigned int fifo_count;

	enum forcewake_domains fw_domains;
	enum forcewake_domains fw_domains_active;
	enum forcewake_domains fw_domains_saved; /* user domains saved for S3 */

	u32 fw_set;
	u32 fw_clear;
	u32 fw_reset;

	struct intel_uncore_forcewake_domain {
		enum forcewake_domain_id id;
		enum forcewake_domains mask;
		unsigned int wake_count;
		bool active;
		struct hrtimer timer;
		i915_reg_t reg_set;
		i915_reg_t reg_ack;
	} fw_domain[FW_DOMAIN_ID_COUNT];

	struct {
		unsigned int count;

		int saved_mmio_check;
		int saved_mmio_debug;
	} user_forcewake;

	int unclaimed_mmio_check;
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_wopcm.h */
struct intel_wopcm {
	u32 size;
	struct {
		u32 base;
		u32 size;
	} guc;
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_guc_fwif.h */
#define GUC_NUM_DOORBELLS	256

enum guc_log_buffer_type {
	GUC_ISR_LOG_BUFFER,
	GUC_DPC_LOG_BUFFER,
	GUC_CRASH_DUMP_LOG_BUFFER,
	GUC_MAX_LOG_BUFFER
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_guc_ct.h */
struct intel_guc_ct_buffer {
	struct guc_ct_buffer_desc *desc;
	u32 *cmds;
};

struct intel_guc_ct_channel {
	struct i915_vma *vma;
	struct intel_guc_ct_buffer ctbs[2];
	u32 owner;
	u32 next_fence;
};

struct intel_guc_ct {
	struct intel_guc_ct_channel host_channel;
	/* other channels are tbd */

	/** @lock: protects pending requests list */
	spinlock_t lock;

	/** @pending_requests: list of requests waiting for response */
	struct list_head pending_requests;

	/** @incoming_requests: list of incoming requests */
	struct list_head incoming_requests;

	/** @worker: worker for handling incoming requests */
	struct work_struct worker;
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_guc_log.h */
struct intel_guc_log {
	u32 level;
	struct i915_vma *vma;
	struct {
		void *buf_addr;
		struct workqueue_struct *flush_wq;
		struct work_struct flush_work;
		struct rchan *channel;
		struct mutex lock;
		u32 full_count;
	} relay;
	/* logging related stats */
	struct {
		u32 sampled_overflow;
		u32 overflow;
		u32 flush;
	} stats[GUC_MAX_LOG_BUFFER];
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_uc_fw.h */
enum intel_uc_fw_status {
	INTEL_UC_FIRMWARE_FAIL = -1,
	INTEL_UC_FIRMWARE_NONE = 0,
	INTEL_UC_FIRMWARE_PENDING,
	INTEL_UC_FIRMWARE_SUCCESS
};

enum intel_uc_fw_type {
	INTEL_UC_FW_TYPE_GUC,
	INTEL_UC_FW_TYPE_HUC
};

struct intel_uc_fw {
	const char *path;
	size_t size;
	struct drm_i915_gem_object *obj;
	enum intel_uc_fw_status fetch_status;
	enum intel_uc_fw_status load_status;

	/*
	 * The firmware build process will generate a version header file with major and
	 * minor version defined. The versions are built into CSS header of firmware.
	 * i915 kernel driver set the minimal firmware version required per platform.
	 */
	u16 major_ver_wanted;
	u16 minor_ver_wanted;
	u16 major_ver_found;
	u16 minor_ver_found;

	enum intel_uc_fw_type type;
	u32 header_size;
	u32 header_offset;
	u32 rsa_size;
	u32 rsa_offset;
	u32 ucode_size;
	u32 ucode_offset;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_gtt.h */
#define I915_MAX_NUM_FENCES 32

typedef u32 gen6_pte_t;

#define I915_PDES			512

#define GEN8_PML4ES_PER_PML4		512

struct intel_rotation_info {
	struct intel_rotation_plane_info {
		/* tiles */
		unsigned int width, height, stride, offset;
	} plane[2];
} __packed;

struct intel_partial_info {
	u64 offset;
	unsigned int size;
} __packed;

enum i915_ggtt_view_type {
	I915_GGTT_VIEW_NORMAL = 0,
	I915_GGTT_VIEW_ROTATED = sizeof(struct intel_rotation_info),
	I915_GGTT_VIEW_PARTIAL = sizeof(struct intel_partial_info),
};

struct i915_ggtt_view {
	enum i915_ggtt_view_type type;
	union {
		/* Members need to contain no holes/padding */
		struct intel_partial_info partial;
		struct intel_rotation_info rotated;
	};
};

enum i915_cache_level;

struct i915_page_dma {
	struct page *page;
	int order;
	union {
		dma_addr_t daddr;

		/* For gen6/gen7 only. This is the offset in the GGTT
		 * where the page directory entries for PPGTT begin
		 */
		u32 ggtt_offset;
	};
};

struct i915_page_directory {
	struct i915_page_dma base;

	struct i915_page_table *page_table[I915_PDES]; /* PDEs */
	unsigned int used_pdes;
};

struct i915_page_directory_pointer {
	struct i915_page_dma base;
	struct i915_page_directory **page_directory;
	unsigned int used_pdpes;
};

struct i915_pml4 {
	struct i915_page_dma base;
	struct i915_page_directory_pointer *pdps[GEN8_PML4ES_PER_PML4];
};

struct i915_vma_ops {
	/* Map an object into an address space with the given cache flags. */
	int (*bind_vma)(struct i915_vma *vma,
			enum i915_cache_level cache_level,
			u32 flags);
	/*
	 * Unmap an object from an address space. This usually consists of
	 * setting the valid PTE entries to a reserved scratch page.
	 */
	void (*unbind_vma)(struct i915_vma *vma);

	int (*set_pages)(struct i915_vma *vma);
	void (*clear_pages)(struct i915_vma *vma);
};

struct pagestash {
	spinlock_t lock;
	struct pagevec pvec;
};

struct i915_address_space {
	struct drm_mm mm;
	struct drm_i915_private *i915;
	struct device *dma;
	/* Every address space belongs to a struct file - except for the global
	 * GTT that is owned by the driver (and so @file is set to NULL). In
	 * principle, no information should leak from one context to another
	 * (or between files/processes etc) unless explicitly shared by the
	 * owner. Tracking the owner is important in order to free up per-file
	 * objects along with the file, to aide resource tracking, and to
	 * assign blame.
	 */
	struct drm_i915_file_private *file;
	u64 total;		/* size addr space maps (ex. 2GB for ggtt) */
	u64 reserved;		/* size addr space reserved */

	bool closed;

	struct mutex mutex; /* protects vma and our lists */

	struct i915_page_dma scratch_page;
	struct i915_page_table *scratch_pt;
	struct i915_page_directory *scratch_pd;
	struct i915_page_directory_pointer *scratch_pdp; /* GEN8+ & 48b PPGTT */

	/**
	 * List of objects currently involved in rendering.
	 *
	 * Includes buffers having the contents of their GPU caches
	 * flushed, not necessarily primitives. last_read_req
	 * represents when the rendering involved will be completed.
	 *
	 * A reference is held on the buffer while on this list.
	 */
	struct list_head active_list;

	/**
	 * LRU list of objects which are not in the ringbuffer and
	 * are ready to unbind, but are still in the GTT.
	 *
	 * last_read_req is NULL while an object is in this list.
	 *
	 * A reference is not held on the buffer while on this list,
	 * as merely being GTT-bound shouldn't prevent its being
	 * freed, and we'll pull it off the list in the free path.
	 */
	struct list_head inactive_list;

	/**
	 * List of vma that have been unbound.
	 *
	 * A reference is not held on the buffer while on this list.
	 */
	struct list_head unbound_list;

	struct pagestash free_pages;

	/* Some systems require uncached updates of the page directories */
	bool pt_kmap_wc:1;

	/* Some systems support read-only mappings for GGTT and/or PPGTT */
	bool has_read_only:1;

	/* FIXME: Need a more generic return type */
	gen6_pte_t (*pte_encode)(dma_addr_t addr,
				 enum i915_cache_level level,
				 u32 flags); /* Create a valid PTE */
	/* flags for pte_encode */
	int (*allocate_va_range)(struct i915_address_space *vm,
				 u64 start, u64 length);
	void (*clear_range)(struct i915_address_space *vm,
			    u64 start, u64 length);
	void (*insert_page)(struct i915_address_space *vm,
			    dma_addr_t addr,
			    u64 offset,
			    enum i915_cache_level cache_level,
			    u32 flags);
	void (*insert_entries)(struct i915_address_space *vm,
			       struct i915_vma *vma,
			       enum i915_cache_level cache_level,
			       u32 flags);
	void (*cleanup)(struct i915_address_space *vm);

	struct i915_vma_ops vma_ops;

	I915_SELFTEST_DECLARE(struct fault_attr fault_attr);
	I915_SELFTEST_DECLARE(bool scrub_64K);
};

struct i915_ggtt {
	struct i915_address_space vm;

	struct io_mapping iomap;	/* Mapping to our CPU mappable region */
	struct resource gmadr;          /* GMADR resource */
	resource_size_t mappable_end;	/* End offset that we can CPU map */

	/** "Graphics Stolen Memory" holds the global PTEs */
	void __iomem *gsm;
	void (*invalidate)(struct drm_i915_private *dev_priv);

	bool do_idle_maps;

	int mtrr;

	u32 pin_bias;

	struct drm_mm_node error_capture;
};

struct i915_hw_ppgtt {
	struct i915_address_space vm;
	struct kref ref;

	unsigned long pd_dirty_rings;
	union {
		struct i915_pml4 pml4;		/* GEN8+ & 48b PPGTT */
		struct i915_page_directory_pointer pdp;	/* GEN8+ */
		struct i915_page_directory pd;		/* GEN6-7 */
	};

	void (*debug_dump)(struct i915_hw_ppgtt *ppgtt, struct seq_file *m);
};

#define INTEL_MAX_PPAT_ENTRIES 8

struct intel_ppat_entry {
	struct intel_ppat *ppat;
	struct kref ref;
	u8 value;
};

struct intel_ppat {
	struct intel_ppat_entry entries[INTEL_MAX_PPAT_ENTRIES];
	DECLARE_BITMAP(used, INTEL_MAX_PPAT_ENTRIES);
	DECLARE_BITMAP(dirty, INTEL_MAX_PPAT_ENTRIES);
	unsigned int max_entries;
	u8 clear_value;
	/*
	 * Return a score to show how two PPAT values match,
	 * a INTEL_PPAT_PERFECT_MATCH indicates a perfect match
	 */
	unsigned int (*match)(u8 src, u8 dst);
	void (*update_hw)(struct drm_i915_private *i915);

	struct drm_i915_private *i915;
};

#define PIN_NONBLOCK		BIT_ULL(0)
#define PIN_MAPPABLE		BIT_ULL(1)

#define PIN_NONFAULT		BIT_ULL(3)

#define PIN_MBZ			BIT_ULL(5) /* I915_VMA_PIN_OVERFLOW */
#define PIN_GLOBAL		BIT_ULL(6) /* I915_VMA_GLOBAL_BIND */
#define PIN_USER		BIT_ULL(7) /* I915_VMA_LOCAL_BIND */

#define PIN_OFFSET_FIXED	BIT_ULL(11)

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_fence_reg.h */
struct drm_i915_fence_reg {
	struct list_head link;
	struct drm_i915_private *i915;
	struct i915_vma *vma;
	int pin_count;
	int id;
	/**
	 * Whether the tiling parameters for the currently
	 * associated fence register have changed. Note that
	 * for the purposes of tracking tiling changes we also
	 * treat the unfenced register, the register slot that
	 * the object occupies whilst it executes a fenced
	 * command (such as BLT on gen2/3), as a "fence".
	 */
	bool dirty;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_gem_object.h */
struct drm_i915_gem_object_ops {
	unsigned int flags;
#define I915_GEM_OBJECT_HAS_STRUCT_PAGE	BIT(0)
	int (*get_pages)(struct drm_i915_gem_object *);
	void (*put_pages)(struct drm_i915_gem_object *, struct sg_table *);

	int (*pwrite)(struct drm_i915_gem_object *,
		      const struct drm_i915_gem_pwrite *);

	int (*dmabuf_export)(struct drm_i915_gem_object *);
	void (*release)(struct drm_i915_gem_object *);
};

struct drm_i915_gem_object {
	struct drm_gem_object base;

	const struct drm_i915_gem_object_ops *ops;

	/**
	 * @vma_list: List of VMAs backed by this object
	 *
	 * The VMA on this list are ordered by type, all GGTT vma are placed
	 * at the head and all ppGTT vma are placed at the tail. The different
	 * types of GGTT vma are unordered between themselves, use the
	 * @vma_tree (which has a defined order between all VMA) to find an
	 * exact match.
	 */
	struct list_head vma_list;
	/**
	 * @vma_tree: Ordered tree of VMAs backed by this object
	 *
	 * All VMA created for this object are placed in the @vma_tree for
	 * fast retrieval via a binary search in i915_vma_instance().
	 * They are also added to @vma_list for easy iteration.
	 */
	struct rb_root vma_tree;

	/**
	 * @lut_list: List of vma lookup entries in use for this object.
	 *
	 * If this object is closed, we need to remove all of its VMA from
	 * the fast lookup index in associated contexts; @lut_list provides
	 * this translation from object to context->handles_vma.
	 */
	struct list_head lut_list;

	/** Stolen memory for this object, instead of being backed by shmem. */
	struct drm_mm_node *stolen;
	union {
		struct rcu_head rcu;
		struct llist_node freed;
	};

	/**
	 * Whether the object is currently in the GGTT mmap.
	 */
	unsigned int userfault_count;
	struct list_head userfault_link;

	struct list_head batch_pool_link;
	I915_SELFTEST_DECLARE(struct list_head st_link);

	unsigned long flags;

	/**
	 * Have we taken a reference for the object for incomplete GPU
	 * activity?
	 */

	/*
	 * Is the object to be mapped as read-only to the GPU
	 * Only honoured if hardware has relevant pte bit
	 */
	unsigned int cache_level:3;
	unsigned int cache_coherent:2;
	unsigned int cache_dirty:1;

	/**
	 * @read_domains: Read memory domains.
	 *
	 * These monitor which caches contain read/write data related to the
	 * object. When transitioning from one set of domains to another,
	 * the driver is called to ensure that caches are suitably flushed and
	 * invalidated.
	 */
	u16 read_domains;

	/**
	 * @write_domain: Corresponding unique write memory domain.
	 */
	u16 write_domain;

	atomic_t frontbuffer_bits;
	unsigned int frontbuffer_ggtt_origin; /* write once */
	struct i915_gem_active frontbuffer_write;

	/** Current tiling stride for the object, if it's tiled. */
	unsigned int tiling_and_stride;

	/** Count of VMA actually bound by this object */
	unsigned int bind_count;
	unsigned int active_count;
	/** Count of how many global VMA are currently pinned for use by HW */
	unsigned int pin_global;

	struct {
		struct mutex lock; /* protects the pages and their use */
		atomic_t pages_pin_count;

		struct sg_table *pages;
		void *mapping;

		/* TODO: whack some of this into the error state */
		struct i915_page_sizes {
			/**
			 * The sg mask of the pages sg_table. i.e the mask of
			 * of the lengths for each sg entry.
			 */
			unsigned int phys;

			/**
			 * The gtt page sizes we are allowed to use given the
			 * sg mask and the supported page sizes. This will
			 * express the smallest unit we can use for the whole
			 * object, as well as the larger sizes we may be able
			 * to use opportunistically.
			 */
			unsigned int sg;

			/**
			 * The actual gtt page size usage. Since we can have
			 * multiple vma associated with this object we need to
			 * prevent any trampling of state, hence a copy of this
			 * struct also lives in each vma, therefore the gtt
			 * value here should only be read/write through the vma.
			 */
			unsigned int gtt;
		} page_sizes;

		I915_SELFTEST_DECLARE(unsigned int page_mask);

		struct i915_gem_object_page_iter {
			struct scatterlist *sg_pos;
			unsigned int sg_idx; /* in pages, but 32bit eek! */

			struct radix_tree_root radix;
			struct mutex lock; /* protects this cache */
		} get_page;

		/**
		 * Element within i915->mm.unbound_list or i915->mm.bound_list,
		 * locked by i915->mm.obj_lock.
		 */
		struct list_head link;

		/**
		 * Advice: are the backing pages purgeable?
		 */
		unsigned int madv:2;

		/**
		 * This is set if the object has been written to since the
		 * pages were last acquired.
		 */
		bool dirty:1;

		/**
		 * This is set if the object has been pinned due to unknown
		 * swizzling.
		 */
		bool quirked:1;
	} mm;

	/** Breadcrumb of last rendering to the buffer.
	 * There can only be one writer, but we allow for multiple readers.
	 * If there is a writer that necessarily implies that all other
	 * read requests are complete - but we may only be lazily clearing
	 * the read requests. A read request is naturally the most recent
	 * request on a ring, so we may have two different write and read
	 * requests on one ring where the write request is older than the
	 * read request. This allows for the CPU to read from an active
	 * buffer by only waiting for the write to complete.
	 */
	struct reservation_object *resv;

	/** References from framebuffers, locks out tiling changes. */
	unsigned int framebuffer_references;

	/** Record of address bit 17 of each page at last unbind. */
	unsigned long *bit_17;

	union {
		struct i915_gem_userptr {
			uintptr_t ptr;

			struct i915_mm_struct *mm;
			struct i915_mmu_object *mmu_object;
			struct work_struct *work;
		} userptr;

		unsigned long scratch;

		void *gvt_info;
	};

	/** for phys allocated objects */
	struct drm_dma_handle *phys_handle;

	struct reservation_object __builtin_resv;
};

__attribute__((nonnull))
static inline struct drm_i915_gem_object *
i915_gem_object_get(struct drm_i915_gem_object *obj)
{
	drm_gem_object_get(&obj->base);
	return obj;
}

static inline void
i915_gem_object_set_readonly(struct drm_i915_gem_object *obj)
{
	obj->base.vma_node.readonly = true;
}

static inline bool
i915_gem_object_is_readonly(const struct drm_i915_gem_object *obj)
{
	return obj->base.vma_node.readonly;
}

static inline bool
i915_gem_object_has_struct_page(const struct drm_i915_gem_object *obj)
{
	return obj->ops->flags & I915_GEM_OBJECT_HAS_STRUCT_PAGE;
}

/* klp-ccp: from drivers/gpu/drm/i915/i915_vma.h */
struct i915_vma {
	struct drm_mm_node node;
	struct drm_i915_gem_object *obj;
	struct i915_address_space *vm;
	const struct i915_vma_ops *ops;
	struct drm_i915_fence_reg *fence;
	struct reservation_object *resv; /** Alias of obj->resv */
	struct sg_table *pages;
	void __iomem *iomap;
	void *private; /* owned by creator */
	u64 size;
	u64 display_alignment;
	struct i915_page_sizes page_sizes;

	u32 fence_size;
	u32 fence_alignment;

	/**
	 * Count of the number of times this vma has been opened by different
	 * handles (but same file) for execbuf, i.e. the number of aliases
	 * that exist in the ctx->handle_vmas LUT for this vma.
	 */
	unsigned int open_count;
	unsigned long flags;

#define I915_VMA_PIN_MASK 0xf
#define I915_VMA_PIN_OVERFLOW	BIT(5)

#define I915_VMA_GLOBAL_BIND	BIT(6)
#define I915_VMA_LOCAL_BIND	BIT(7)
#define I915_VMA_BIND_MASK (I915_VMA_GLOBAL_BIND | I915_VMA_LOCAL_BIND | I915_VMA_PIN_OVERFLOW)

#define I915_VMA_CAN_FENCE	BIT(9)
	unsigned int active_count;
	struct rb_root active;
	struct i915_gem_active last_active;
	struct i915_gem_active last_fence;

	/**
	 * Support different GGTT views into the same object.
	 * This means there can be multiple VMA mappings per object and per VM.
	 * i915_ggtt_view_type is used to distinguish between those entries.
	 * The default one of zero (I915_GGTT_VIEW_NORMAL) is default and also
	 * assumed in GEM functions which take no ggtt view parameter.
	 */
	struct i915_ggtt_view ggtt_view;

	/** This object's place on the active/inactive lists */
	struct list_head vm_link;

	struct list_head obj_link; /* Link in the object's VMA list */
	struct rb_node obj_node;
	struct hlist_node obj_hash;

	/** This vma's place in the execbuf reservation list */
	struct list_head exec_link;
	struct list_head reloc_link;

	/** This vma's place in the eviction list */
	struct list_head evict_link;

	struct list_head closed_link;

	/**
	 * Used for performing relocations during execbuffer insertion.
	 */
	unsigned int *exec_flags;
	struct hlist_node exec_node;
	u32 exec_handle;
};

static inline bool i915_vma_is_active(struct i915_vma *vma)
{
	return vma->active_count;
}

bool i915_vma_is_ggtt(const struct i915_vma *vma);

static inline bool i915_vma_is_map_and_fenceable(const struct i915_vma *vma)
{
	return vma->flags & I915_VMA_CAN_FENCE;
}

static inline u32 i915_ggtt_offset(const struct i915_vma *vma)
{
	GEM_BUG_ON(!i915_vma_is_ggtt(vma));
	GEM_BUG_ON(!vma->node.allocated);
	GEM_BUG_ON(upper_32_bits(vma->node.start));
	GEM_BUG_ON(upper_32_bits(vma->node.start + vma->node.size - 1));
	return lower_32_bits(vma->node.start);
}

static inline struct i915_vma *i915_vma_get(struct i915_vma *vma)
{
	i915_gem_object_get(vma->obj);
	return vma;
}

bool i915_vma_misplaced(const struct i915_vma *vma,
			u64 size, u64 alignment, u64 flags);

extern int (*klpe___i915_vma_do_pin)(struct i915_vma *vma,
		      u64 size, u64 alignment, u64 flags);
static inline int __must_check
klpr_i915_vma_pin(struct i915_vma *vma, u64 size, u64 alignment, u64 flags)
{
	BUILD_BUG_ON(PIN_MBZ != I915_VMA_PIN_OVERFLOW);
	BUILD_BUG_ON(PIN_GLOBAL != I915_VMA_GLOBAL_BIND);
	BUILD_BUG_ON(PIN_USER != I915_VMA_LOCAL_BIND);

	/* Pin early to prevent the shrinker/eviction logic from destroying
	 * our vma as we insert and bind.
	 */
	if (likely(((++vma->flags ^ flags) & I915_VMA_BIND_MASK) == 0)) {
		GEM_BUG_ON(!drm_mm_node_allocated(&vma->node));
		GEM_BUG_ON(i915_vma_misplaced(vma, size, alignment, flags));
		return 0;
	}

	return (*klpe___i915_vma_do_pin)(vma, size, alignment, flags);
}

static inline int i915_vma_pin_count(const struct i915_vma *vma)
{
	return vma->flags & I915_VMA_PIN_MASK;
}

static inline bool i915_vma_is_pinned(const struct i915_vma *vma)
{
	return i915_vma_pin_count(vma);
}

static inline void __i915_vma_unpin(struct i915_vma *vma)
{
	vma->flags--;
}

static inline void i915_vma_unpin(struct i915_vma *vma)
{
	GEM_BUG_ON(!i915_vma_is_pinned(vma));
	GEM_BUG_ON(!drm_mm_node_allocated(&vma->node));
	__i915_vma_unpin(vma);
}

static inline void __i915_vma_unpin_fence(struct i915_vma *vma)
{
	GEM_BUG_ON(vma->fence->pin_count <= 0);
	vma->fence->pin_count--;
}

/* klp-ccp: from drivers/gpu/drm/i915/intel_guc.h */
struct guc_preempt_work {
	struct work_struct work;
	struct intel_engine_cs *engine;
};

struct intel_guc {
	struct intel_uc_fw fw;
	struct intel_guc_log log;
	struct intel_guc_ct ct;

	/* Log snapshot if GuC errors during load */
	struct drm_i915_gem_object *load_err_log;

	/* intel_guc_recv interrupt related state */
	spinlock_t irq_lock;
	bool interrupts_enabled;
	unsigned int msg_enabled_mask;

	struct i915_vma *ads_vma;
	struct i915_vma *stage_desc_pool;
	void *stage_desc_pool_vaddr;
	struct ida stage_ids;
	struct i915_vma *shared_data;
	void *shared_data_vaddr;

	struct intel_guc_client *execbuf_client;
	struct intel_guc_client *preempt_client;

	struct guc_preempt_work preempt_work[I915_NUM_ENGINES];
	struct workqueue_struct *preempt_wq;

	DECLARE_BITMAP(doorbell_bitmap, GUC_NUM_DOORBELLS);
	/* Cyclic counter mod pagesize	*/
	u32 db_cacheline;

	/* GuC's FW specific registers used in MMIO send */
	struct {
		u32 base;
		unsigned int count;
		enum forcewake_domains fw_domains;
	} send_regs;

	/* To serialize the intel_guc_send actions */
	struct mutex send_mutex;

	/* GuC's FW specific send function */
	int (*send)(struct intel_guc *guc, const u32 *data, u32 len,
		    u32 *response_buf, u32 response_buf_size);

	/* GuC's FW specific event handler function */
	void (*handler)(struct intel_guc *guc);

	/* GuC's FW specific notify function */
	void (*notify)(struct intel_guc *guc);
};

/* klp-ccp: from drivers/gpu/drm/i915/intel_huc.h */
struct intel_huc {
	/* Generic uC firmware management */
	struct intel_uc_fw fw;

	/* HuC-specific additions */
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_gpu_error.h */
struct i915_gpu_error {
	/* For hangcheck timer */

	struct delayed_work hangcheck_work;

	/* For reset and error_state handling. */
	spinlock_t lock;
	/* Protected by the above dev->gpu_error.lock. */
	struct i915_gpu_state *first_error;

	atomic_t pending_fb_pin;

	unsigned long missed_irq_rings;

	/**
	 * State variable controlling the reset flow and count
	 *
	 * This is a counter which gets incremented when reset is triggered,
	 *
	 * Before the reset commences, the I915_RESET_BACKOFF bit is set
	 * meaning that any waiters holding onto the struct_mutex should
	 * relinquish the lock immediately in order for the reset to start.
	 *
	 * If reset is not completed successfully, the I915_WEDGE bit is
	 * set meaning that hardware is terminally sour and there is no
	 * recovery. All waiters on the reset_queue will be woken when
	 * that happens.
	 *
	 * This counter is used by the wait_seqno code to notice that reset
	 * event happened and it needs to restart the entire ioctl (since most
	 * likely the seqno it waited for won't ever signal anytime soon).
	 *
	 * This is important for lock-free wait paths, where no contended lock
	 * naturally enforces the correct ordering between the bail-out of the
	 * waiter and the gpu reset work code.
	 */
	unsigned long reset_count;

	/**
	 * flags: Control various stages of the GPU reset
	 *
	 * #I915_RESET_BACKOFF - When we start a reset, we want to stop any
	 * other users acquiring the struct_mutex. To do this we set the
	 * #I915_RESET_BACKOFF bit in the error flags when we detect a reset
	 * and then check for that bit before acquiring the struct_mutex (in
	 * i915_mutex_lock_interruptible()?). I915_RESET_BACKOFF serves a
	 * secondary role in preventing two concurrent global reset attempts.
	 *
	 * #I915_RESET_HANDOFF - To perform the actual GPU reset, we need the
	 * struct_mutex. We try to acquire the struct_mutex in the reset worker,
	 * but it may be held by some long running waiter (that we cannot
	 * interrupt without causing trouble). Once we are ready to do the GPU
	 * reset, we set the I915_RESET_HANDOFF bit and wakeup any waiters. If
	 * they already hold the struct_mutex and want to participate they can
	 * inspect the bit and do the reset directly, otherwise the worker
	 * waits for the struct_mutex.
	 *
	 * #I915_RESET_ENGINE[num_engines] - Since the driver doesn't need to
	 * acquire the struct_mutex to reset an engine, we need an explicit
	 * flag to prevent two concurrent reset attempts in the same engine.
	 * As the number of engines continues to grow, allocate the flags from
	 * the most significant bits.
	 *
	 * #I915_WEDGED - If reset fails and we can no longer use the GPU,
	 * we set the #I915_WEDGED bit. Prior to command submission, e.g.
	 * i915_request_alloc(), this bit is checked and the sequence
	 * aborted (with -EIO reported to userspace) if set.
	 */
	unsigned long flags;

	/** Number of times an engine has been reset */
	u32 reset_engine_count[I915_NUM_ENGINES];

	/** Set of stalled engines with guilty requests, in the current reset */
	u32 stalled_mask;

	/** Reason for the current *global* reset */
	const char *reason;

	/**
	 * Waitqueue to signal when a hang is detected. Used to for waiters
	 * to release the struct_mutex for the reset to procede.
	 */
	wait_queue_head_t wait_queue;

	/**
	 * Waitqueue to signal when the reset has completed. Used by clients
	 * that wait for dev_priv->mm.wedged to settle.
	 */
	wait_queue_head_t reset_queue;

	/* For missed irq/seqno simulation. */
	unsigned long test_irq_rings;
};

/* klp-ccp: from drivers/gpu/drm/i915/i915_drv.h */
enum hpd_pin {
	HPD_NONE = 0,
	HPD_TV = HPD_NONE,     /* TV is known to be unreliable */
	HPD_CRT,
	HPD_SDVO_B,
	HPD_SDVO_C,
	HPD_PORT_A,
	HPD_PORT_B,
	HPD_PORT_C,
	HPD_PORT_D,
	HPD_PORT_E,
	HPD_PORT_F,
	HPD_NUM_PINS
};

struct i915_hotplug {
	struct work_struct hotplug_work;

	struct {
		unsigned long last_jiffies;
		int count;
		enum {
			HPD_ENABLED = 0,
			HPD_DISABLED = 1,
			HPD_MARK_DISABLED = 2
		} state;
	} stats[HPD_NUM_PINS];
	u32 event_bits;
	struct delayed_work reenable_work;

	u32 long_port_mask;
	u32 short_port_mask;
	struct work_struct dig_port_work;

	struct work_struct poll_init_work;
	bool poll_enabled;

	unsigned int hpd_storm_threshold;

	/*
	 * if we get a HPD irq from DP and a HPD irq from non-DP
	 * the non-DP HPD could block the workqueue on a mode config
	 * mutex getting, that userspace may have taken. However
	 * userspace is waiting on the DP workqueue to run which is
	 * blocked behind the non-DP one.
	 */
	struct workqueue_struct *dp_wq;
};

#define I915_GEM_GPU_DOMAINS \
	(I915_GEM_DOMAIN_RENDER | \
	 I915_GEM_DOMAIN_SAMPLER | \
	 I915_GEM_DOMAIN_COMMAND | \
	 I915_GEM_DOMAIN_INSTRUCTION | \
	 I915_GEM_DOMAIN_VERTEX)

struct drm_i915_file_private {
	struct drm_i915_private *dev_priv;
	struct drm_file *file;

	struct {
		spinlock_t lock;
		struct list_head request_list;
/* 20ms is a fairly arbitrary limit (greater than the average frame time)
 * chosen to prevent the CPU getting more than a frame ahead of the GPU
 * (when using lax throttling for the frontbuffer). We also use it to
 * offer free GPU waitboosts for severely congested workloads.
 */
	} mm;
	struct idr context_idr;

	struct intel_rps_client {
		atomic_t boosts;
	} rps_client;

	unsigned int bsd_engine;

/*
 * Every context ban increments per client ban score. Also
 * hangs in short succession increments ban score. If ban threshold
 * is reached, client is considered banned and submitting more work
 * will fail. This is a stop gap measure to limit the badly behaving
 * clients access to gpu. Note that unbannable contexts never increment
 * the client ban score.
 */
	/** ban_score: Accumulated score of all ctx bans and fast hangs. */
	atomic_t ban_score;
	unsigned long hang_timestamp;
};

struct sdvo_device_mapping {
	u8 initialized;
	u8 dvo_port;
	u8 slave_addr;
	u8 dvo_wiring;
	u8 i2c_pin;
	u8 ddc_pin;
};

struct intel_atomic_state;

struct intel_initial_plane_config;

struct intel_cdclk_state;

struct drm_i915_display_funcs {
	void (*get_cdclk)(struct drm_i915_private *dev_priv,
			  struct intel_cdclk_state *cdclk_state);
	void (*set_cdclk)(struct drm_i915_private *dev_priv,
			  const struct intel_cdclk_state *cdclk_state);
	int (*get_fifo_size)(struct drm_i915_private *dev_priv,
			     enum i9xx_plane_id i9xx_plane);
	int (*compute_pipe_wm)(struct intel_crtc_state *cstate);
	int (*compute_intermediate_wm)(struct drm_device *dev,
				       struct intel_crtc *intel_crtc,
				       struct intel_crtc_state *newstate);
	void (*initial_watermarks)(struct intel_atomic_state *state,
				   struct intel_crtc_state *cstate);
	void (*atomic_update_watermarks)(struct intel_atomic_state *state,
					 struct intel_crtc_state *cstate);
	void (*optimize_watermarks)(struct intel_atomic_state *state,
				    struct intel_crtc_state *cstate);
	int (*compute_global_watermarks)(struct drm_atomic_state *state);
	void (*update_wm)(struct intel_crtc *crtc);
	int (*modeset_calc_cdclk)(struct drm_atomic_state *state);
	/* Returns the active state of the crtc, and if the crtc is active,
	 * fills out the pipe-config with the hw state. */
	bool (*get_pipe_config)(struct intel_crtc *,
				struct intel_crtc_state *);
	void (*get_initial_plane_config)(struct intel_crtc *,
					 struct intel_initial_plane_config *);
	int (*crtc_compute_clock)(struct intel_crtc *crtc,
				  struct intel_crtc_state *crtc_state);
	void (*crtc_enable)(struct intel_crtc_state *pipe_config,
			    struct drm_atomic_state *old_state);
	void (*crtc_disable)(struct intel_crtc_state *old_crtc_state,
			     struct drm_atomic_state *old_state);
	void (*update_crtcs)(struct drm_atomic_state *state);
	void (*audio_codec_enable)(struct intel_encoder *encoder,
				   const struct intel_crtc_state *crtc_state,
				   const struct drm_connector_state *conn_state);
	void (*audio_codec_disable)(struct intel_encoder *encoder,
				    const struct intel_crtc_state *old_crtc_state,
				    const struct drm_connector_state *old_conn_state);
	void (*fdi_link_train)(struct intel_crtc *crtc,
			       const struct intel_crtc_state *crtc_state);
	void (*init_clock_gating)(struct drm_i915_private *dev_priv);
	void (*hpd_irq_setup)(struct drm_i915_private *dev_priv);
	/* clock updates for mode set */
	/* cursor updates */
	/* render clock increase/decrease */
	/* display clock increase/decrease */
	/* pll clock increase/decrease */

	void (*load_csc_matrix)(struct drm_crtc_state *crtc_state);
	void (*load_luts)(struct drm_crtc_state *crtc_state);
};

struct intel_csr {
	struct work_struct work;
	const char *fw_path;
	uint32_t *dmc_payload;
	uint32_t dmc_fw_size;
	uint32_t version;
	uint32_t mmio_count;
	i915_reg_t mmioaddr[8];
	uint32_t mmiodata[8];
	uint32_t dc_state;
	uint32_t allowed_dc_mask;
};

enum i915_cache_level {
	I915_CACHE_NONE = 0,
	I915_CACHE_LLC, /* also used for snoopable memory on non-LLC */
	I915_CACHE_L3_LLC, /* gen7+, L3 sits between the domain specifc
			      caches, eg sampler/render caches, and the
			      large Last-Level-Cache. LLC is coherent with
			      the CPU, but L3 is only visible to the GPU. */
	I915_CACHE_WT, /* hsw:gt3e WriteThrough for scanouts */
};

#define I915_COLOR_UNEVICTABLE (-1) /* a non-vma sharing the address space */

struct intel_fbc {
	/* This is always the inner lock when overlapping with struct_mutex and
	 * it's the outer lock when overlapping with stolen_lock. */
	struct mutex lock;
	unsigned threshold;
	unsigned int possible_framebuffer_bits;
	unsigned int busy_bits;
	unsigned int visible_pipes_mask;
	struct intel_crtc *crtc;

	struct drm_mm_node compressed_fb;
	struct drm_mm_node *compressed_llb;

	bool false_color;

	bool enabled;
	bool active;
	bool flip_pending;

	bool underrun_detected;
	struct work_struct underrun_work;

	/*
	 * Due to the atomic rules we can't access some structures without the
	 * appropriate locking, so we cache information here in order to avoid
	 * these problems.
	 */
	struct intel_fbc_state_cache {
		struct i915_vma *vma;
		unsigned long flags;

		struct {
			unsigned int mode_flags;
			uint32_t hsw_bdw_pixel_rate;
		} crtc;

		struct {
			unsigned int rotation;
			int src_w;
			int src_h;
			bool visible;
			/*
			 * Display surface base address adjustement for
			 * pageflips. Note that on gen4+ this only adjusts up
			 * to a tile, offsets within a tile are handled in
			 * the hw itself (with the TILEOFF register).
			 */
			int adjusted_x;
			int adjusted_y;

			int y;
		} plane;

		struct {
			const struct drm_format_info *format;
			unsigned int stride;
		} fb;
	} state_cache;

	/*
	 * This structure contains everything that's relevant to program the
	 * hardware registers. When we want to figure out if we need to disable
	 * and re-enable FBC for a new configuration we just check if there's
	 * something different in the struct. The genx_fbc_activate functions
	 * are supposed to read from it in order to program the registers.
	 */
	struct intel_fbc_reg_params {
		struct i915_vma *vma;
		unsigned long flags;

		struct {
			enum pipe pipe;
			enum i9xx_plane_id i9xx_plane;
			unsigned int fence_y_offset;
		} crtc;

		struct {
			const struct drm_format_info *format;
			unsigned int stride;
		} fb;

		int cfb_size;
		unsigned int gen9_wa_cfb_stride;
	} params;

	const char *no_fbc_reason;
};

enum drrs_refresh_rate_type {
	DRRS_HIGH_RR,
	DRRS_LOW_RR,
	DRRS_MAX_RR, /* RR count */
};

enum drrs_support_type {
	DRRS_NOT_SUPPORTED = 0,
	STATIC_DRRS_SUPPORT = 1,
	SEAMLESS_DRRS_SUPPORT = 2
};

struct i915_drrs {
	struct mutex mutex;
	struct delayed_work work;
	struct intel_dp *dp;
	unsigned busy_frontbuffer_bits;
	enum drrs_refresh_rate_type refresh_rate_type;
	enum drrs_support_type type;
};

struct i915_psr {
	struct mutex lock;
	bool sink_support;
	struct intel_dp *enabled;
	bool active;
	struct work_struct work;
	unsigned busy_frontbuffer_bits;
	bool sink_psr2_support;
	bool link_standby;
	bool colorimetry_support;
	bool alpm;
	bool psr2_enabled;
	u8 sink_sync_latency;
	bool debug;
	ktime_t last_entry_attempt;
	ktime_t last_exit;
};

enum intel_pch {
	PCH_NONE = 0,	/* No PCH present */
	PCH_IBX,	/* Ibexpeak PCH */
	PCH_CPT,	/* Cougarpoint/Pantherpoint PCH */
	PCH_LPT,	/* Lynxpoint/Wildcatpoint PCH */
	PCH_SPT,        /* Sunrisepoint PCH */
	PCH_KBP,        /* Kaby Lake PCH */
	PCH_CNP,        /* Cannon/Comet Lake PCH */
	PCH_ICP,	/* Ice Lake PCH */
	PCH_NOP,	/* PCH without south display */
};

struct intel_gmbus {
	struct i2c_adapter adapter;
	u32 force_bit;
	u32 reg0;
	i915_reg_t gpio_reg;
	struct i2c_algo_bit_data bit_algo;
	struct drm_i915_private *dev_priv;
};

struct i915_suspend_saved_registers {
	u32 saveDSPARB;
	u32 saveFBC_CONTROL;
	u32 saveCACHE_MODE_0;
	u32 saveMI_ARB_STATE;
	u32 saveSWF0[16];
	u32 saveSWF1[16];
	u32 saveSWF3[3];
	uint64_t saveFENCE[I915_MAX_NUM_FENCES];
	u32 savePCH_PORT_HOTPLUG;
	u16 saveGCDGMBUS;
};

struct vlv_s0ix_state {
	/* GAM */
	u32 wr_watermark;
	u32 gfx_prio_ctrl;
	u32 arb_mode;
	u32 gfx_pend_tlb0;
	u32 gfx_pend_tlb1;
	u32 lra_limits[GEN7_LRA_LIMITS_REG_NUM];
	u32 media_max_req_count;
	u32 gfx_max_req_count;
	u32 render_hwsp;
	u32 ecochk;
	u32 bsd_hwsp;
	u32 blt_hwsp;
	u32 tlb_rd_addr;

	/* MBC */
	u32 g3dctl;
	u32 gsckgctl;
	u32 mbctl;

	/* GCP */
	u32 ucgctl1;
	u32 ucgctl3;
	u32 rcgctl1;
	u32 rcgctl2;
	u32 rstctl;
	u32 misccpctl;

	/* GPM */
	u32 gfxpause;
	u32 rpdeuhwtc;
	u32 rpdeuc;
	u32 ecobus;
	u32 pwrdwnupctl;
	u32 rp_down_timeout;
	u32 rp_deucsw;
	u32 rcubmabdtmr;
	u32 rcedata;
	u32 spare2gh;

	/* Display 1 CZ domain */
	u32 gt_imr;
	u32 gt_ier;
	u32 pm_imr;
	u32 pm_ier;
	u32 gt_scratch[GEN7_GT_SCRATCH_REG_NUM];

	/* GT SA CZ domain */
	u32 tilectl;
	u32 gt_fifoctl;
	u32 gtlc_wake_ctrl;
	u32 gtlc_survive;
	u32 pmwgicz;

	/* Display 2 CZ domain */
	u32 gu_ctl0;
	u32 gu_ctl1;
	u32 pcbr;
	u32 clock_gate_dis2;
};

struct intel_rps_ei {
	ktime_t ktime;
	u32 render_c0;
	u32 media_c0;
};

struct intel_rps {
	/*
	 * work, interrupts_enabled and pm_iir are protected by
	 * dev_priv->irq_lock
	 */
	struct work_struct work;
	bool interrupts_enabled;
	u32 pm_iir;

	/* PM interrupt bits that should never be masked */
	u32 pm_intrmsk_mbz;

	/* Frequencies are stored in potentially platform dependent multiples.
	 * In other words, *_freq needs to be multiplied by X to be interesting.
	 * Soft limits are those which are used for the dynamic reclocking done
	 * by the driver (raise frequencies under heavy loads, and lower for
	 * lighter loads). Hard limits are those imposed by the hardware.
	 *
	 * A distinction is made for overclocking, which is never enabled by
	 * default, and is considered to be above the hard limit if it's
	 * possible at all.
	 */
	u8 cur_freq;		/* Current frequency (cached, may not == HW) */
	u8 min_freq_softlimit;	/* Minimum frequency permitted by the driver */
	u8 max_freq_softlimit;	/* Max frequency permitted by the driver */
	u8 max_freq;		/* Maximum frequency, RP0 if not overclocking */
	u8 min_freq;		/* AKA RPn. Minimum frequency */
	u8 boost_freq;		/* Frequency to request when wait boosting */
	u8 idle_freq;		/* Frequency to request when we are idle */
	u8 efficient_freq;	/* AKA RPe. Pre-determined balanced frequency */
	u8 rp1_freq;		/* "less than" RP0 power/freqency */
	u8 rp0_freq;		/* Non-overclocked max frequency. */
	u16 gpll_ref_freq;	/* vlv/chv GPLL reference frequency */

	int last_adj;

	struct {
		struct mutex mutex;

		enum { LOW_POWER, BETWEEN, HIGH_POWER } mode;
		unsigned int interactive;

		u8 up_threshold; /* Current %busy required to uplock */
		u8 down_threshold; /* Current %busy required to downclock */
	} power;

	bool enabled;
	atomic_t num_waiters;
	atomic_t boosts;

	/* manual wa residency calculations */
	struct intel_rps_ei ei;
};

struct intel_rc6 {
	bool enabled;
	u64 prev_hw_residency[4];
	u64 cur_residency[4];
};

struct intel_llc_pstate {
	bool enabled;
};

struct intel_gen6_power_mgmt {
	struct intel_rps rps;
	struct intel_rc6 rc6;
	struct intel_llc_pstate llc_pstate;
};

struct intel_ilk_power_mgmt {
	u8 cur_delay;
	u8 min_delay;
	u8 max_delay;
	u8 fmax;
	u8 fstart;

	u64 last_count1;
	unsigned long last_time1;
	unsigned long chipset_power;
	u64 last_count2;
	u64 last_time2;
	unsigned long gfx_power;
	u8 corr;

	int c_m;
	int r_t;
};

struct i915_power_domains {
	/*
	 * Power wells needed for initialization at driver init and suspend
	 * time are on. They are kept on until after the first modeset.
	 */
	bool init_power_on;
	bool initializing;
	int power_well_count;

	struct mutex lock;
	int domain_use_count[POWER_DOMAIN_NUM];
	struct i915_power_well *power_wells;
};

#define MAX_L3_SLICES 2
struct intel_l3_parity {
	u32 *remap_info[MAX_L3_SLICES];
	struct work_struct error_work;
	int which_slice;
};

struct i915_gem_mm {
	/** Memory allocator for GTT stolen memory */
	struct drm_mm stolen;
	/** Protects the usage of the GTT stolen memory allocator. This is
	 * always the inner lock when overlapping with struct_mutex. */
	struct mutex stolen_lock;

	/* Protects bound_list/unbound_list and #drm_i915_gem_object.mm.link */
	spinlock_t obj_lock;

	/** List of all objects in gtt_space. Used to restore gtt
	 * mappings on resume */
	struct list_head bound_list;
	/**
	 * List of objects which are not bound to the GTT (thus
	 * are idle and not used by the GPU). These objects may or may
	 * not actually have any pages attached.
	 */
	struct list_head unbound_list;

	/** List of all objects in gtt_space, currently mmaped by userspace.
	 * All objects within this list must also be on bound_list.
	 */
	struct list_head userfault_list;

	/**
	 * List of objects which are pending destruction.
	 */
	struct llist_head free_list;
	struct work_struct free_work;
	spinlock_t free_lock;
	/**
	 * Count of objects pending destructions. Used to skip needlessly
	 * waiting on an RCU barrier if no objects are waiting to be freed.
	 */
	atomic_t free_count;

	/**
	 * Small stash of WC pages
	 */
	struct pagestash wc_stash;

	/**
	 * tmpfs instance used for shmem backed objects
	 */
	struct vfsmount *gemfs;

	/** PPGTT used for aliasing the PPGTT with the GTT */
	struct i915_hw_ppgtt *aliasing_ppgtt;

	struct notifier_block oom_notifier;
	struct notifier_block vmap_notifier;
	struct shrinker shrinker;

	/** LRU list of objects with fence regs on them. */
	struct list_head fence_list;

	/**
	 * Workqueue to fault in userptr pages, flushed by the execbuf
	 * when required but otherwise left to userspace to try again
	 * on EAGAIN.
	 */
	struct workqueue_struct *userptr_wq;

	u64 unordered_timeline;

	/* the indicator for dispatch video commands on two BSD rings */
	atomic_t bsd_engine_dispatch_index;

	/** Bit 6 swizzling required for X tiling */
	uint32_t bit_6_swizzle_x;
	/** Bit 6 swizzling required for Y tiling */
	uint32_t bit_6_swizzle_y;

	/* accounting, useful for userland debugging */
	spinlock_t object_stat_lock;
	u64 object_memory;
	u32 object_count;
};

struct ddi_vbt_port_info {
	int max_tmds_clock;

	/*
	 * This is an index in the HDMI/DVI DDI buffer translation table.
	 * The special value HDMI_LEVEL_SHIFT_UNKNOWN means the VBT didn't
	 * populate this field.
	 */
	uint8_t hdmi_level_shift;

	uint8_t supports_dvi:1;
	uint8_t supports_hdmi:1;
	uint8_t supports_dp:1;
	uint8_t supports_edp:1;

	uint8_t alternate_aux_channel;
	uint8_t alternate_ddc_pin;

	uint8_t dp_boost_level;
	uint8_t hdmi_boost_level;
	int dp_max_link_rate;		/* 0 for not limited by VBT */
};

enum psr_lines_to_wait {
	PSR_0_LINES_TO_WAIT = 0,
	PSR_1_LINE_TO_WAIT,
	PSR_4_LINES_TO_WAIT,
	PSR_8_LINES_TO_WAIT
};

struct intel_vbt_data {
	struct drm_display_mode *lfp_lvds_vbt_mode; /* if any */
	struct drm_display_mode *sdvo_lvds_vbt_mode; /* if any */

	/* Feature bits */
	unsigned int int_tv_support:1;
	unsigned int lvds_dither:1;
	unsigned int int_crt_support:1;
	unsigned int lvds_use_ssc:1;
	unsigned int int_lvds_support:1;
	unsigned int display_clock_mode:1;
	unsigned int fdi_rx_polarity_inverted:1;
	unsigned int panel_type:4;
	int lvds_ssc_freq;
	unsigned int bios_lvds_val; /* initial [PCH_]LVDS reg val in VBIOS */

	enum drrs_support_type drrs_type;

	struct {
		int rate;
		int lanes;
		int preemphasis;
		int vswing;
		bool low_vswing;
		bool initialized;
		int bpp;
		struct edp_power_seq pps;
	} edp;

	struct {
		bool enable;
		bool full_link;
		bool require_aux_wakeup;
		int idle_frames;
		enum psr_lines_to_wait lines_to_wait;
		int tp1_wakeup_time_us;
		int tp2_tp3_wakeup_time_us;
	} psr;

	struct {
		u16 pwm_freq_hz;
		bool present;
		bool active_low_pwm;
		u8 min_brightness;	/* min_brightness/255 of max */
		u8 controller;		/* brightness controller number */
		enum intel_backlight_type type;
	} backlight;

	/* MIPI DSI */
	struct {
		u16 panel_id;
		struct mipi_config *config;
		struct mipi_pps_data *pps;
		u16 bl_ports;
		u16 cabc_ports;
		u8 seq_version;
		u32 size;
		u8 *data;
		const u8 *sequence[MIPI_SEQ_MAX];
		u8 *deassert_seq; /* Used by fixup_mipi_sequences() */
	} dsi;

	int crt_ddc_pin;

	int child_dev_num;
	struct child_device_config *child_dev;

	struct ddi_vbt_port_info ddi_port_info[I915_MAX_PORTS];
	struct sdvo_device_mapping sdvo_mappings[2];
};

enum intel_ddb_partitioning {
	INTEL_DDB_PART_1_2,
	INTEL_DDB_PART_5_6, /* IVB+ */
};

struct ilk_wm_values {
	uint32_t wm_pipe[3];
	uint32_t wm_lp[3];
	uint32_t wm_lp_spr[3];
	uint32_t wm_linetime[3];
	bool enable_fbc_wm;
	enum intel_ddb_partitioning partitioning;
};

struct g4x_pipe_wm {
	uint16_t plane[I915_MAX_PLANES];
	uint16_t fbc;
};

struct g4x_sr_wm {
	uint16_t plane;
	uint16_t cursor;
	uint16_t fbc;
};

struct vlv_wm_ddl_values {
	uint8_t plane[I915_MAX_PLANES];
};

struct vlv_wm_values {
	struct g4x_pipe_wm pipe[3];
	struct g4x_sr_wm sr;
	struct vlv_wm_ddl_values ddl[3];
	uint8_t level;
	bool cxsr;
};

struct g4x_wm_values {
	struct g4x_pipe_wm pipe[2];
	struct g4x_sr_wm sr;
	struct g4x_sr_wm hpll;
	bool cxsr;
	bool hpll_en;
	bool fbc_en;
};

struct skl_ddb_entry {
	uint16_t start, end;	/* in number of blocks, 'end' is exclusive */
};

struct skl_ddb_allocation {
	/* packed/y */
	struct skl_ddb_entry plane[I915_MAX_PIPES][I915_MAX_PLANES];
	struct skl_ddb_entry uv_plane[I915_MAX_PIPES][I915_MAX_PLANES];
	u8 enabled_slices; /* GEN11 has configurable 2 slices */
};

struct skl_ddb_values {
	unsigned dirty_pipes;
	struct skl_ddb_allocation ddb;
};

struct i915_runtime_pm {
	atomic_t wakeref_count;
	bool suspended;
	bool irqs_enabled;
};

enum intel_pipe_crc_source {
	INTEL_PIPE_CRC_SOURCE_NONE,
	INTEL_PIPE_CRC_SOURCE_PLANE1,
	INTEL_PIPE_CRC_SOURCE_PLANE2,
	INTEL_PIPE_CRC_SOURCE_PF,
	INTEL_PIPE_CRC_SOURCE_PIPE,
	/* TV/DP on pre-gen5/vlv can't use the pipe source. */
	INTEL_PIPE_CRC_SOURCE_TV,
	INTEL_PIPE_CRC_SOURCE_DP_B,
	INTEL_PIPE_CRC_SOURCE_DP_C,
	INTEL_PIPE_CRC_SOURCE_DP_D,
	INTEL_PIPE_CRC_SOURCE_AUTO,
	INTEL_PIPE_CRC_SOURCE_MAX,
};

struct intel_pipe_crc {
	spinlock_t lock;
	int skipped;
	enum intel_pipe_crc_source source;
};

struct i915_frontbuffer_tracking {
	spinlock_t lock;

	/*
	 * Tracking bits for delayed frontbuffer flushing du to gpu activity or
	 * scheduled flips.
	 */
	unsigned busy_bits;
	unsigned flip_bits;
};

struct i915_wa_reg {
	u32 addr;
	u32 value;
	/* bitmask representing WA bits */
	u32 mask;
};

#define I915_MAX_WA_REGS 16

struct i915_workarounds {
	struct i915_wa_reg reg[I915_MAX_WA_REGS];
	u32 count;
};

struct i915_virtual_gpu {
	bool active;
	u32 caps;
};

struct i915_oa_config {
	char uuid[UUID_STRING_LEN + 1];
	int id;

	const struct i915_oa_reg *mux_regs;
	u32 mux_regs_len;
	const struct i915_oa_reg *b_counter_regs;
	u32 b_counter_regs_len;
	const struct i915_oa_reg *flex_regs;
	u32 flex_regs_len;

	struct attribute_group sysfs_metric;
	struct attribute *attrs[2];
	struct device_attribute sysfs_metric_id;

	atomic_t ref_count;
};

struct i915_perf_stream;

struct i915_oa_ops {
	/**
	 * @is_valid_b_counter_reg: Validates register's address for
	 * programming boolean counters for a particular platform.
	 */
	bool (*is_valid_b_counter_reg)(struct drm_i915_private *dev_priv,
				       u32 addr);

	/**
	 * @is_valid_mux_reg: Validates register's address for programming mux
	 * for a particular platform.
	 */
	bool (*is_valid_mux_reg)(struct drm_i915_private *dev_priv, u32 addr);

	/**
	 * @is_valid_flex_reg: Validates register's address for programming
	 * flex EU filtering for a particular platform.
	 */
	bool (*is_valid_flex_reg)(struct drm_i915_private *dev_priv, u32 addr);

	/**
	 * @init_oa_buffer: Resets the head and tail pointers of the
	 * circular buffer for periodic OA reports.
	 *
	 * Called when first opening a stream for OA metrics, but also may be
	 * called in response to an OA buffer overflow or other error
	 * condition.
	 *
	 * Note it may be necessary to clear the full OA buffer here as part of
	 * maintaining the invariable that new reports must be written to
	 * zeroed memory for us to be able to reliable detect if an expected
	 * report has not yet landed in memory.  (At least on Haswell the OA
	 * buffer tail pointer is not synchronized with reports being visible
	 * to the CPU)
	 */
	void (*init_oa_buffer)(struct drm_i915_private *dev_priv);

	/**
	 * @enable_metric_set: Selects and applies any MUX configuration to set
	 * up the Boolean and Custom (B/C) counters that are part of the
	 * counter reports being sampled. May apply system constraints such as
	 * disabling EU clock gating as required.
	 */
	int (*enable_metric_set)(struct drm_i915_private *dev_priv,
				 const struct i915_oa_config *oa_config);

	/**
	 * @disable_metric_set: Remove system constraints associated with using
	 * the OA unit.
	 */
	void (*disable_metric_set)(struct drm_i915_private *dev_priv);

	/**
	 * @oa_enable: Enable periodic sampling
	 */
	void (*oa_enable)(struct drm_i915_private *dev_priv);

	/**
	 * @oa_disable: Disable periodic sampling
	 */
	void (*oa_disable)(struct drm_i915_private *dev_priv);

	/**
	 * @read: Copy data from the circular OA buffer into a given userspace
	 * buffer.
	 */
	int (*read)(struct i915_perf_stream *stream,
		    char __user *buf,
		    size_t count,
		    size_t *offset);

	/**
	 * @oa_hw_tail_read: read the OA tail pointer register
	 *
	 * In particular this enables us to share all the fiddly code for
	 * handling the OA unit tail pointer race that affects multiple
	 * generations.
	 */
	u32 (*oa_hw_tail_read)(struct drm_i915_private *dev_priv);
};

struct intel_cdclk_state {
	unsigned int cdclk, vco, ref, bypass;
	u8 voltage_level;
};

struct drm_i915_private {
	struct drm_device drm;

	struct kmem_cache *objects;
	struct kmem_cache *vmas;
	struct kmem_cache *luts;
	struct kmem_cache *requests;
	struct kmem_cache *dependencies;
	struct kmem_cache *priorities;

	const struct intel_device_info info;
	struct intel_runtime_info __runtime; /* Use RUNTIME_INFO() to access. */
	struct intel_driver_caps caps;

	/**
	 * Data Stolen Memory - aka "i915 stolen memory" gives us the start and
	 * end of stolen which we can optionally use to create GEM objects
	 * backed by stolen memory. Note that stolen_usable_size tells us
	 * exactly how much of this we are actually allowed to use, given that
	 * some portion of it is in fact reserved for use by hardware functions.
	 */
	struct resource dsm;
	/**
	 * Reseved portion of Data Stolen Memory
	 */
	struct resource dsm_reserved;

	/*
	 * Stolen memory is segmented in hardware with different portions
	 * offlimits to certain functions.
	 *
	 * The drm_mm is initialised to the total accessible range, as found
	 * from the PCI config. On Broadwell+, this is further restricted to
	 * avoid the first page! The upper end of stolen memory is reserved for
	 * hardware functions and similarly removed from the accessible range.
	 */
	resource_size_t stolen_usable_size;	/* Total size minus reserved ranges */

	void __iomem *regs;

	struct intel_uncore uncore;

	struct i915_virtual_gpu vgpu;

	struct intel_gvt *gvt;

	struct intel_wopcm wopcm;

	struct intel_huc huc;
	struct intel_guc guc;

	struct intel_csr csr;

	struct intel_gmbus gmbus[GMBUS_NUM_PINS];

	/** gmbus_mutex protects against concurrent usage of the single hw gmbus
	 * controller on different i2c buses. */
	struct mutex gmbus_mutex;

	/**
	 * Base address of the gmbus and gpio block.
	 */
	uint32_t gpio_mmio_base;

	/* MMIO base address for MIPI regs */
	uint32_t mipi_mmio_base;

	uint32_t psr_mmio_base;

	uint32_t pps_mmio_base;

	wait_queue_head_t gmbus_wait_queue;

	struct pci_dev *bridge_dev;
	struct intel_engine_cs *engine[I915_NUM_ENGINES];
	/* Context used internally to idle the GPU and setup initial state */
	struct i915_gem_context *kernel_context;
	/* Context only to be used for injecting preemption commands */
	struct i915_gem_context *preempt_context;
	struct intel_engine_cs *engine_class[MAX_ENGINE_CLASS + 1]
					    [MAX_ENGINE_INSTANCE + 1];

	struct drm_dma_handle *status_page_dmah;
	struct resource mch_res;

	/* protects the irq masks */
	spinlock_t irq_lock;

	bool display_irqs_enabled;

	/* To control wakeup latency, e.g. for irq-driven dp aux transfers. */
	struct pm_qos_request pm_qos;

	/* Sideband mailbox protection */
	struct mutex sb_lock;

	/** Cached value of IMR to avoid reads in updating the bitfield */
	union {
		u32 irq_mask;
		u32 de_irq_mask[I915_MAX_PIPES];
	};
	u32 gt_irq_mask;
	u32 pm_imr;
	u32 pm_ier;
	u32 pm_rps_events;
	u32 pm_guc_events;
	u32 pipestat_irq_mask[I915_MAX_PIPES];

	struct i915_hotplug hotplug;
	struct intel_fbc fbc;
	struct i915_drrs drrs;
	struct intel_opregion opregion;
	struct intel_vbt_data vbt;

	bool preserve_bios_swizzle;

	/* overlay */
	struct intel_overlay *overlay;

	/* backlight registers and fields in struct intel_panel */
	struct mutex backlight_lock;

	/* LVDS info */
	bool no_aux_handshake;

	/* protects panel power sequencer state */
	struct mutex pps_mutex;

	struct drm_i915_fence_reg fence_regs[I915_MAX_NUM_FENCES]; /* assume 965 */
	int num_fence_regs; /* 8 on pre-965, 16 otherwise */

	unsigned int fsb_freq, mem_freq, is_ddr3;
	unsigned int skl_preferred_vco_freq;
	unsigned int max_cdclk_freq;

	unsigned int max_dotclk_freq;
	unsigned int rawclk_freq;
	unsigned int hpll_freq;
	unsigned int fdi_pll_freq;
	unsigned int czclk_freq;

	struct {
		/*
		 * The current logical cdclk state.
		 * See intel_atomic_state.cdclk.logical
		 *
		 * For reading holding any crtc lock is sufficient,
		 * for writing must hold all of them.
		 */
		struct intel_cdclk_state logical;
		/*
		 * The current actual cdclk state.
		 * See intel_atomic_state.cdclk.actual
		 */
		struct intel_cdclk_state actual;
		/* The current hardware cdclk state */
		struct intel_cdclk_state hw;

		int force_min_cdclk;
	} cdclk;

	/**
	 * wq - Driver workqueue for GEM.
	 *
	 * NOTE: Work items scheduled here are not allowed to grab any modeset
	 * locks, for otherwise the flushing done in the pageflip code will
	 * result in deadlocks.
	 */
	struct workqueue_struct *wq;

	/* ordered wq for modesets */
	struct workqueue_struct *modeset_wq;

	/* Display functions */
	struct drm_i915_display_funcs display;

	/* PCH chipset type */
	enum intel_pch pch_type;
	unsigned short pch_id;

	unsigned long quirks;

	struct drm_atomic_state *modeset_restore_state;
	struct drm_modeset_acquire_ctx reset_ctx;

	struct i915_ggtt ggtt; /* VM representing the global address space */

	struct i915_gem_mm mm;
	DECLARE_HASHTABLE(mm_structs, 7);
	struct mutex mm_lock;

	struct intel_ppat ppat;

	/* Kernel Modesetting */

	struct intel_crtc *plane_to_crtc_mapping[I915_MAX_PIPES];
	struct intel_crtc *pipe_to_crtc_mapping[I915_MAX_PIPES];

#ifdef CONFIG_DEBUG_FS
	struct intel_pipe_crc pipe_crc[I915_MAX_PIPES];
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	int num_shared_dpll;
	struct intel_shared_dpll shared_dplls[I915_NUM_PLLS];
	const struct intel_dpll_mgr *dpll_mgr;

	/*
	 * dpll_lock serializes intel_{prepare,enable,disable}_shared_dpll.
	 * Must be global rather than per dpll, because on some platforms
	 * plls share registers.
	 */
	struct mutex dpll_lock;

	unsigned int active_crtcs;
	/* minimum acceptable cdclk for each pipe */
	int min_cdclk[I915_MAX_PIPES];
	/* minimum acceptable voltage level for each pipe */
	u8 min_voltage_level[I915_MAX_PIPES];

	int dpio_phy_iosf_port[I915_NUM_PHYS_VLV];

	struct i915_workarounds workarounds;
	struct i915_wa_list gt_wa_list;

	struct i915_frontbuffer_tracking fb_tracking;

	struct intel_atomic_helper {
		struct llist_head free_list;
		struct work_struct free_work;
	} atomic_helper;

	u16 orig_clock;

	bool mchbar_need_disable;

	struct intel_l3_parity l3_parity;

	/* Cannot be determined by PCIID. You must always read a register. */
	u32 edram_cap;

	/*
	 * Protects RPS/RC6 register access and PCU communication.
	 * Must be taken after struct_mutex if nested. Note that
	 * this lock may be held for long periods of time when
	 * talking to hw - so only take it when talking to hw!
	 */
	struct mutex pcu_lock;

	/* gen6+ GT PM state */
	struct intel_gen6_power_mgmt gt_pm;

	/* ilk-only ips/rps state. Everything in here is protected by the global
	 * mchdev_lock in intel_pm.c */
	struct intel_ilk_power_mgmt ips;

	struct i915_power_domains power_domains;

	struct i915_psr psr;

	struct i915_gpu_error gpu_error;

	struct drm_i915_gem_object *vlv_pctx;

	/* list of fbdev register on this device */
	struct intel_fbdev *fbdev;
	struct work_struct fbdev_suspend_work;

	struct drm_property *broadcast_rgb_property;
	struct drm_property *force_audio_property;

	/* hda/i915 audio component */
	struct i915_audio_component *audio_component;
	bool audio_component_registered;
	/**
	 * av_mutex - mutex for audio/video sync
	 *
	 */
	struct mutex av_mutex;
	int audio_power_refcount;

	struct {
		struct mutex mutex;
		struct list_head list;
		struct llist_head free_list;
		struct work_struct free_work;

		/* The hw wants to have a stable context identifier for the
		 * lifetime of the context (for OA, PASID, faults, etc).
		 * This is limited in execlists to 21 bits.
		 */
		struct ida hw_ida;
		struct list_head hw_id_list;
	} contexts;

	u32 fdi_rx_config;

	/* Shadow for DISPLAY_PHY_CONTROL which can't be safely read */
	u32 chv_phy_control;
	/*
	 * Shadows for CHV DPLL_MD regs to keep the state
	 * checker somewhat working in the presence hardware
	 * crappiness (can't read out DPLL_MD for pipes B & C).
	 */
	u32 chv_dpll_md[I915_MAX_PIPES];
	u32 bxt_phy_grc;

	u32 suspend_count;
	bool power_domains_suspended;
	struct i915_suspend_saved_registers regfile;
	struct vlv_s0ix_state vlv_s0ix_state;

	enum {
		I915_SAGV_UNKNOWN = 0,
		I915_SAGV_DISABLED,
		I915_SAGV_ENABLED,
		I915_SAGV_NOT_CONTROLLED
	} sagv_status;

	struct {
		/*
		 * Raw watermark latency values:
		 * in 0.1us units for WM0,
		 * in 0.5us units for WM1+.
		 */
		/* primary */
		uint16_t pri_latency[5];
		/* sprite */
		uint16_t spr_latency[5];
		/* cursor */
		uint16_t cur_latency[5];
		/*
		 * Raw watermark memory latency values
		 * for SKL for all 8 levels
		 * in 1us units.
		 */
		uint16_t skl_latency[8];

		/* current hardware state */
		union {
			struct ilk_wm_values hw;
			struct skl_ddb_values skl_hw;
			struct vlv_wm_values vlv;
			struct g4x_wm_values g4x;
		};

		uint8_t max_level;

		/*
		 * Should be held around atomic WM register writing; also
		 * protects * intel_crtc->wm.active and
		 * cstate->wm.need_postvbl_update.
		 */
		struct mutex wm_mutex;

		/*
		 * Set during HW readout of watermarks/DDB.  Some platforms
		 * need to know when we're still using BIOS-provided values
		 * (which we don't fully trust).
		 */
		bool distrust_bios_wm;
	} wm;

	struct i915_runtime_pm runtime_pm;

	struct {
		bool initialized;

		struct kobject *metrics_kobj;
		struct ctl_table_header *sysctl_header;

		/*
		 * Lock associated with adding/modifying/removing OA configs
		 * in dev_priv->perf.metrics_idr.
		 */
		struct mutex metrics_lock;

		/*
		 * List of dynamic configurations, you need to hold
		 * dev_priv->perf.metrics_lock to access it.
		 */
		struct idr metrics_idr;

		/*
		 * Lock associated with anything below within this structure
		 * except exclusive_stream.
		 */
		struct mutex lock;
		struct list_head streams;

		struct {
			/*
			 * The stream currently using the OA unit. If accessed
			 * outside a syscall associated to its file
			 * descriptor, you need to hold
			 * dev_priv->drm.struct_mutex.
			 */
			struct i915_perf_stream *exclusive_stream;

			struct intel_context *pinned_ctx;
			u32 specific_ctx_id;
			u32 specific_ctx_id_mask;

			struct hrtimer poll_check_timer;
			wait_queue_head_t poll_wq;
			bool pollin;

			/**
			 * For rate limiting any notifications of spurious
			 * invalid OA reports
			 */
			struct ratelimit_state spurious_report_rs;

			bool periodic;
			int period_exponent;

			struct i915_oa_config test_config;

			struct {
				struct i915_vma *vma;
				u8 *vaddr;
				u32 last_ctx_id;
				int format;
				int format_size;

				/**
				 * Locks reads and writes to all head/tail state
				 *
				 * Consider: the head and tail pointer state
				 * needs to be read consistently from a hrtimer
				 * callback (atomic context) and read() fop
				 * (user context) with tail pointer updates
				 * happening in atomic context and head updates
				 * in user context and the (unlikely)
				 * possibility of read() errors needing to
				 * reset all head/tail state.
				 *
				 * Note: Contention or performance aren't
				 * currently a significant concern here
				 * considering the relatively low frequency of
				 * hrtimer callbacks (5ms period) and that
				 * reads typically only happen in response to a
				 * hrtimer event and likely complete before the
				 * next callback.
				 *
				 * Note: This lock is not held *while* reading
				 * and copying data to userspace so the value
				 * of head observed in htrimer callbacks won't
				 * represent any partial consumption of data.
				 */
				spinlock_t ptr_lock;

				/**
				 * One 'aging' tail pointer and one 'aged'
				 * tail pointer ready to used for reading.
				 *
				 * Initial values of 0xffffffff are invalid
				 * and imply that an update is required
				 * (and should be ignored by an attempted
				 * read)
				 */
				struct {
					u32 offset;
				} tails[2];

				/**
				 * Index for the aged tail ready to read()
				 * data up to.
				 */
				unsigned int aged_tail_idx;

				/**
				 * A monotonic timestamp for when the current
				 * aging tail pointer was read; used to
				 * determine when it is old enough to trust.
				 */
				u64 aging_timestamp;

				/**
				 * Although we can always read back the head
				 * pointer register, we prefer to avoid
				 * trusting the HW state, just to avoid any
				 * risk that some hardware condition could
				 * somehow bump the head pointer unpredictably
				 * and cause us to forward the wrong OA buffer
				 * data to userspace.
				 */
				u32 head;
			} oa_buffer;

			u32 gen7_latched_oastatus1;
			u32 ctx_oactxctrl_offset;
			u32 ctx_flexeu0_offset;

			/**
			 * The RPT_ID/reason field for Gen8+ includes a bit
			 * to determine if the CTX ID in the report is valid
			 * but the specific bit differs between Gen 8 and 9
			 */
			u32 gen8_valid_ctx_bit;

			struct i915_oa_ops ops;
			const struct i915_oa_format *oa_formats;
		} oa;
	} perf;

	/* Abstract the submission mechanism (legacy ringbuffer or execlists) away */
	struct {
		void (*resume)(struct drm_i915_private *);
		void (*cleanup_engine)(struct intel_engine_cs *engine);

		struct list_head timelines;

		struct list_head active_rings;
		struct list_head closed_vma;
		u32 active_requests;
		u32 request_serial;

		/**
		 * Is the GPU currently considered idle, or busy executing
		 * userspace requests? Whilst idle, we allow runtime power
		 * management to power down the hardware and display clocks.
		 * In order to reduce the effect on performance, there
		 * is a slight delay before we do so.
		 */
		bool awake;

		/**
		 * The number of times we have woken up.
		 */
		unsigned int epoch;

		/**
		 * We leave the user IRQ off as much as possible,
		 * but this means that requests will finish and never
		 * be retired once the system goes idle. Set a timer to
		 * fire periodically while the ring is running. When it
		 * fires, go retire requests.
		 */
		struct delayed_work retire_work;

		/**
		 * When we detect an idle GPU, we want to turn on
		 * powersaving features. So once we see that there
		 * are no more requests outstanding and no more
		 * arrive within a small period of time, we fire
		 * off the idle_work.
		 */
		struct delayed_work idle_work;

		ktime_t last_init_time;
	} gt;

	/* perform PHY state sanity checks? */
	bool chv_phy_assert[2];

	bool ipc_enabled;

	/* Used to save the pipe-to-encoder mapping for audio */
	struct intel_encoder *av_enc_map[I915_MAX_PIPES];

	/* necessary resource sharing with HDMI LPE audio driver. */
	struct {
		struct platform_device *platdev;
		int	irq;
	} lpe_audio;

	struct i915_pmu pmu;

	/*
	 * NOTE: This is the dri1/ums dungeon, don't add stuff here. Your patch
	 * will be rejected. Instead look for a better place.
	 */
};

static inline struct drm_i915_private *to_i915(const struct drm_device *dev)
{
	return container_of(dev, struct drm_i915_private, drm);
}

#define for_each_engine(engine__, dev_priv__, id__) \
	for ((id__) = 0; \
	     (id__) < I915_NUM_ENGINES; \
	     (id__)++) \
		for_each_if ((engine__) = (dev_priv__)->engine[(id__)])

static inline const struct intel_device_info *
intel_info(const struct drm_i915_private *dev_priv)
{
	return &dev_priv->info;
}

#define INTEL_INFO(dev_priv)	intel_info((dev_priv))

#define INTEL_GEN(dev_priv)	((dev_priv)->info.gen)

#define IS_GEN6(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(5)))
#define IS_GEN7(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(6)))

#define IS_GEN9(dev_priv)	(!!((dev_priv)->info.gen_mask & BIT(8)))

#define KLPP_CMDPARSER_USES_GGTT(dev_priv) IS_GEN7(dev_priv)

#define ENGINE_MASK(id)	BIT(id)

#define HAS_ENGINE(dev_priv, id) \
	(!!((dev_priv)->info.ring_mask & ENGINE_MASK(id)))

#define HAS_BSD2(dev_priv)	HAS_ENGINE(dev_priv, VCS2)

#define HAS_LLC(dev_priv)	((dev_priv)->info.has_llc)

#define HAS_64BIT_RELOC(dev_priv) ((dev_priv)->info.has_64bit_reloc)

#define HAS_RESOURCE_STREAMER(dev_priv) ((dev_priv)->info.has_resource_streamer)

/* klp-ccp: from drivers/gpu/drm/i915/i915_drv.h */
bool
i915_gem_object_has_pages(struct drm_i915_gem_object *obj);

bool
i915_gem_object_has_pinned_pages(struct drm_i915_gem_object *obj);

static inline void
__i915_gem_object_unpin_pages(struct drm_i915_gem_object *obj)
{
	GEM_BUG_ON(!i915_gem_object_has_pages(obj));
	GEM_BUG_ON(!i915_gem_object_has_pinned_pages(obj));

	atomic_dec(&obj->mm.pages_pin_count);
}

static inline void
i915_gem_object_unpin_pages(struct drm_i915_gem_object *obj)
{
	__i915_gem_object_unpin_pages(obj);
}

enum i915_map_type {
	I915_MAP_WB = 0,
	I915_MAP_WC,
#define I915_MAP_OVERRIDE BIT(31)
	I915_MAP_FORCE_WB = I915_MAP_WB | I915_MAP_OVERRIDE,
	I915_MAP_FORCE_WC = I915_MAP_WC | I915_MAP_OVERRIDE,
};

static inline void i915_gem_object_unpin_map(struct drm_i915_gem_object *obj)
{
	i915_gem_object_unpin_pages(obj);
}

#define CLFLUSH_BEFORE	BIT(0)
#define CLFLUSH_AFTER	BIT(1)
#define CLFLUSH_FLAGS	(CLFLUSH_BEFORE | CLFLUSH_AFTER)

static inline void
i915_gem_obj_finish_shmem_access(struct drm_i915_gem_object *obj)
{
	i915_gem_object_unpin_pages(obj);
}

static inline struct i915_gem_context *
__i915_gem_context_lookup_rcu(struct drm_i915_file_private *file_priv, u32 id)
{
	return idr_find(&file_priv->context_idr, id);
}

static inline struct i915_gem_context *
i915_gem_context_lookup(struct drm_i915_file_private *file_priv, u32 id)
{
	struct i915_gem_context *ctx;

	rcu_read_lock();
	ctx = __i915_gem_context_lookup_rcu(file_priv, id);
	if (ctx && !kref_get_unless_zero(&ctx->ref))
		ctx = NULL;
	rcu_read_unlock();

	return ctx;
}

static inline void i915_gem_chipset_flush(struct drm_i915_private *dev_priv)
{
	wmb();
	if (INTEL_GEN(dev_priv) < 6)
		intel_gtt_chipset_flush();
}


/* from include/linux/tracepoint.h */
#define KLPR___DECLARE_TRACE(name, proto, args, cond, data_proto, data_args) \
	static struct tracepoint (*klpe___tracepoint_##name);		\
	static inline void klpr_trace_##name(proto)			\
	{								\
		if (unlikely(static_key_enabled(&(*klpe___tracepoint_##name).key))) \
			__DO_TRACE(&(*klpe___tracepoint_##name),	\
				TP_PROTO(data_proto),			\
				TP_ARGS(data_args),			\
				TP_CONDITION(cond), 0);		\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {		\
			rcu_read_lock_sched_notrace();			\
			rcu_dereference_sched((*klpe___tracepoint_##name).funcs); \
			rcu_read_unlock_sched_notrace();		\
		}							\
	}								\

#define KLPR_DECLARE_TRACE(name, proto, args)				\
	KLPR___DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
			cpu_online(raw_smp_processor_id()),		\
			PARAMS(void *__data, proto),			\
			PARAMS(__data, args))

#define KLPR_DEFINE_EVENT(template, name, proto, args)		\
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))

#define KLPR_TRACE_EVENT(name, proto, args)	\
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))


/* Livepatch specific */
int klp_bsc1173663_cmd_parser_resolve_kallsyms(void);
int klp_bsc1173663_gem_resolve_kallsyms(void);
int klp_bsc1173663_gem_execbuffer_resolve_kallsyms(void);

int klp_bsc1173663_cmd_parser_init(void);
void klp_bsc1173663_cmd_parser_cleanup(void);


struct i915_vma *
klpp_i915_gem_object_pin(struct drm_i915_gem_object *obj,
			 struct i915_address_space *vm,
			 const struct i915_ggtt_view *view,
			 u64 size,
			 u64 alignment,
			 u64 flags);

int klpp_intel_engine_cmd_parser(struct i915_gem_context *ctx,
			    struct intel_engine_cs *engine,
			    struct drm_i915_gem_object *batch_obj,
			    u64 batch_start,
			    u32 batch_start_offset,
			    u32 batch_len,
			    struct drm_i915_gem_object *shadow_batch_obj,
			    u64 shadow_batch_start);

static inline bool klpp_is_gen9_blt(const struct intel_engine_cs *ring)
{
	return (ring->id == BCS && IS_GEN9(ring->i915));
}

#endif
