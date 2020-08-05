/*
 * bsc1173663_cmd_parser.c
 *
 * Fix for CVE-2019-0155, bsc#1173663 (i915_cmd_parser.c part)
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
#include "bsc1173663_common.h"
#include "../kallsyms_relocs.h"

/* klp-ccp: from drivers/gpu/drm/i915/i915_reg.h */
#define BCS_SWCTRL _MMIO(0x22200)

#define BCS_GPR(n)        _MMIO(0x22600 + (n) * 8)
#define BCS_GPR_UDW(n)    _MMIO(0x22600 + (n) * 8 + 4)

#define RENDER_RING_BASE        0x02000
#define BSD_RING_BASE           0x04000

#define BLT_RING_BASE           0x22000

#define RING_TIMESTAMP(base)            _MMIO((base)+0x358)
#define RING_TIMESTAMP_UDW(base)        _MMIO((base)+0x358 + 4)

/* klp-ccp: from include/drm/drm_cache.h */
static void (*klpe_drm_clflush_virt_range)(void *addr, unsigned long length);

/* klp-ccp: from drivers/gpu/drm/i915/i915_drv.h */
static struct page *
(*klpe_i915_gem_object_get_page)(struct drm_i915_gem_object *obj,
			 unsigned int n);

static void *__must_check (*klpe_i915_gem_object_pin_map)(struct drm_i915_gem_object *obj,
					   enum i915_map_type type);

static int (*klpe_i915_gem_obj_prepare_shmem_read)(struct drm_i915_gem_object *obj,
				    unsigned int *needs_clflush);
static int (*klpe_i915_gem_obj_prepare_shmem_write)(struct drm_i915_gem_object *obj,
				     unsigned int *needs_clflush);

static bool (*klpe_i915_memcpy_from_wc)(void *dst, const void *src, unsigned long len);

#define klpr_i915_can_memcpy_from_wc(dst, src, len) \
	(*klpe_i915_memcpy_from_wc)((void *)((unsigned long)(dst) | (unsigned long)(src) | (len)), NULL, 0)

/* klp-ccp: from drivers/gpu/drm/i915/i915_cmd_parser.c */
struct drm_i915_cmd_descriptor {
	/*
	 * Flags describing how the command parser processes the command.
	 *
	 * CMD_DESC_FIXED: The command has a fixed length if this is set,
	 *                 a length mask if not set
	 * CMD_DESC_SKIP: The command is allowed but does not follow the
	 *                standard length encoding for the opcode range in
	 *                which it falls
	 * CMD_DESC_REJECT: The command is never allowed
	 * CMD_DESC_REGISTER: The command should be checked against the
	 *                    register whitelist for the appropriate ring
	 * CMD_DESC_MASTER: The command is allowed if the submitting process
	 *                  is the DRM master
	 */
	u32 flags;
#define CMD_DESC_FIXED    (1<<0)
#define CMD_DESC_SKIP     (1<<1)
#define CMD_DESC_REJECT   (1<<2)
#define CMD_DESC_REGISTER (1<<3)
#define CMD_DESC_BITMASK  (1<<4)
#define CMD_DESC_MASTER   (1<<5)
	struct {
		u32 value;
		u32 mask;
	} cmd;

	/*
	 * The command's length. The command is either fixed length (i.e. does
	 * not include a length field) or has a length field mask. The flag
	 * CMD_DESC_FIXED indicates a fixed length. Otherwise, the command has
	 * a length mask. All command entries in a command table must include
	 * length information.
	 */
	union {
		u32 fixed;
		u32 mask;
	} length;

	/*
	 * Describes where to find a register address in the command to check
	 * against the ring's register whitelist. Only valid if flags has the
	 * CMD_DESC_REGISTER bit set.
	 *
	 * A non-zero step value implies that the command may access multiple
	 * registers in sequence (e.g. LRI), in that case step gives the
	 * distance in dwords between individual offset fields.
	 */
	struct {
		u32 offset;
		u32 mask;
		u32 step;
	} reg;

#define MAX_CMD_DESC_BITMASKS 3
	struct {
		u32 offset;
		u32 mask;
		u32 expected;
		u32 condition_offset;
		u32 condition_mask;
	} bits[MAX_CMD_DESC_BITMASKS];
};

struct drm_i915_cmd_table {
	const struct drm_i915_cmd_descriptor *table;
	int count;
};

#define STD_MI_OPCODE_SHIFT  (32 - 9)
#define STD_3D_OPCODE_SHIFT  (32 - 16)
#define STD_2D_OPCODE_SHIFT  (32 - 10)

#define MIN_OPCODE_SHIFT 16

#define CMD(op, opm, f, lm, fl, ...)				\
	{							\
		.flags = (fl) | ((f) ? CMD_DESC_FIXED : 0),	\
		.cmd = { (op), ~0u << (opm) },			\
		.length = { (lm) },				\
		__VA_ARGS__					\
	}

#define SMI STD_MI_OPCODE_SHIFT

#define F true
#define S CMD_DESC_SKIP

#define W CMD_DESC_REGISTER
#define B CMD_DESC_BITMASK

/* New. */
static const struct drm_i915_cmd_descriptor klpp_gen9_blt_cmds[] = {
	CMD(  MI_NOOP,				SMI,	F,  1,	    S  ),
	CMD(  MI_USER_INTERRUPT,		SMI,	F,  1,	    S  ),
	CMD(  MI_WAIT_FOR_EVENT,		SMI,	F,  1,	    S  ),
	CMD(  MI_FLUSH,				SMI,	F,  1,	    S  ),
	CMD(  MI_ARB_CHECK,			SMI,	F,  1,	    S  ),
	CMD(  MI_REPORT_HEAD,			SMI,	F,  1,	    S  ),
	CMD(  MI_ARB_ON_OFF,			SMI,	F,  1,	    S  ),
	CMD(  MI_SUSPEND_FLUSH,			SMI,	F,  1,	    S  ),
	CMD(  MI_LOAD_SCAN_LINES_INCL,		SMI,   !F,  0x3F,   S  ),
	CMD(  MI_LOAD_SCAN_LINES_EXCL,		SMI,   !F,  0x3F,   S  ),
	CMD(  MI_STORE_DWORD_IMM,		SMI,   !F,  0x3FF,  S  ),
	CMD(  MI_LOAD_REGISTER_IMM(1),		SMI,   !F,  0xFF,   W,
	      .reg = { .offset = 1, .mask = 0x007FFFFC, .step = 2 }    ),
	CMD(  MI_UPDATE_GTT,			SMI,   !F,  0x3FF,  S  ),
	CMD(  MI_STORE_REGISTER_MEM_GEN8,	SMI,	F,  4,	    W,
	      .reg = { .offset = 1, .mask = 0x007FFFFC }	       ),
	CMD(  MI_FLUSH_DW,			SMI,   !F,  0x3F,   S  ),
	CMD(  MI_LOAD_REGISTER_MEM_GEN8,	SMI,	F,  4,	    W,
	      .reg = { .offset = 1, .mask = 0x007FFFFC }	       ),
	CMD(  MI_LOAD_REGISTER_REG,		SMI,	!F,  0xFF,  W,
	      .reg = { .offset = 1, .mask = 0x007FFFFC, .step = 1 }    ),

	/*
	 * We allow BB_START but apply further checks. We just sanitize the
	 * basic fields here.
	 */
#define MI_BB_START_OPERAND_MASK   GENMASK(SMI-1, 0)
#define MI_BB_START_OPERAND_EXPECT (MI_BATCH_PPGTT_HSW | 1)
	CMD(  MI_BATCH_BUFFER_START_GEN8,	SMI,	!F,  0xFF,  B,
	      .bits = {{
			.offset = 0,
			.mask = MI_BB_START_OPERAND_MASK,
			.expected = MI_BB_START_OPERAND_EXPECT,
	      }},						       ),
};

static const struct drm_i915_cmd_descriptor noop_desc =
	CMD(MI_NOOP, SMI, F, 1, S);

#undef SMI

#undef F
#undef S

#undef W
#undef B

/* New. */
static const struct drm_i915_cmd_table klpp_gen9_blt_cmd_table[] = {
	{ klpp_gen9_blt_cmds, ARRAY_SIZE(klpp_gen9_blt_cmds) },
};

struct drm_i915_reg_descriptor {
	i915_reg_t addr;
	u32 mask;
	u32 value;
};

#define REG32(_reg, ...) \
	{ .addr = (_reg), __VA_ARGS__ }

#define REG64_IDX(_reg, idx) \
	{ .addr = _reg(idx) }, \
	{ .addr = _reg ## _UDW(idx) }

/* New. */
static const struct drm_i915_reg_descriptor klpp_gen9_blt_regs[] = {
	REG64_IDX(RING_TIMESTAMP, RENDER_RING_BASE),
	REG64_IDX(RING_TIMESTAMP, BSD_RING_BASE),
	REG32(BCS_SWCTRL),
	REG64_IDX(RING_TIMESTAMP, BLT_RING_BASE),
	REG64_IDX(BCS_GPR, 0),
	REG64_IDX(BCS_GPR, 1),
	REG64_IDX(BCS_GPR, 2),
	REG64_IDX(BCS_GPR, 3),
	REG64_IDX(BCS_GPR, 4),
	REG64_IDX(BCS_GPR, 5),
	REG64_IDX(BCS_GPR, 6),
	REG64_IDX(BCS_GPR, 7),
	REG64_IDX(BCS_GPR, 8),
	REG64_IDX(BCS_GPR, 9),
	REG64_IDX(BCS_GPR, 10),
	REG64_IDX(BCS_GPR, 11),
	REG64_IDX(BCS_GPR, 12),
	REG64_IDX(BCS_GPR, 13),
	REG64_IDX(BCS_GPR, 14),
	REG64_IDX(BCS_GPR, 15),
};

#undef REG64_IDX
#undef REG32

struct drm_i915_reg_table {
	const struct drm_i915_reg_descriptor *regs;
	int num_regs;
	bool master;
};

/* New. */
static const struct drm_i915_reg_table klpp_gen9_blt_reg_tables[] = {
	{ klpp_gen9_blt_regs, ARRAY_SIZE(klpp_gen9_blt_regs), false },
};

/* New. */
static u32 klpp_gen9_blt_get_cmd_length_mask(u32 cmd_header)
{
	u32 client = cmd_header >> INSTR_CLIENT_SHIFT;

	if (client == INSTR_MI_CLIENT || client == INSTR_BC_CLIENT)
		return 0xFF;

	KLPR_DRM_DEBUG_DRIVER("CMD: Abnormal blt cmd length! 0x%08X\n", cmd_header);
	return 0;
}

struct cmd_node {
	const struct drm_i915_cmd_descriptor *desc;
	struct hlist_node node;
};

static inline u32 cmd_header_key(u32 x)
{
	switch (x >> INSTR_CLIENT_SHIFT) {
	default:
	case INSTR_MI_CLIENT:
		return x >> STD_MI_OPCODE_SHIFT;
	case INSTR_RC_CLIENT:
		return x >> STD_3D_OPCODE_SHIFT;
	case INSTR_BC_CLIENT:
		return x >> STD_2D_OPCODE_SHIFT;
	}
}

/*
 * Copy of the original init_hash_table with slightly modified
 * signature for initializing the static klpp_gen9_blt_cmd_hash.
 */
static int klpp_init_hash_table(DECLARE_HASHTABLE((*cmd_hash), I915_CMD_HASH_ORDER),
			   const struct drm_i915_cmd_table *cmd_tables,
			   int cmd_table_count)
{
	int i, j;

	hash_init((*cmd_hash));

	for (i = 0; i < cmd_table_count; i++) {
		const struct drm_i915_cmd_table *table = &cmd_tables[i];

		for (j = 0; j < table->count; j++) {
			const struct drm_i915_cmd_descriptor *desc =
				&table->table[j];
			struct cmd_node *desc_node =
				kmalloc(sizeof(*desc_node), GFP_KERNEL);

			if (!desc_node)
				return -ENOMEM;

			desc_node->desc = desc;
			hash_add((*cmd_hash), &desc_node->node,
				 cmd_header_key(desc->cmd.value));
		}
	}

	return 0;
}

/*
 * Copy of the original fini_hash_table with slightly modified
 * signature for destroying the static klpp_gen9_blt_cmd_hash.
 */
static void klpp_fini_hash_table(DECLARE_HASHTABLE((*cmd_hash), I915_CMD_HASH_ORDER))
{
	struct hlist_node *tmp;
	struct cmd_node *desc_node;
	int i;

	hash_for_each_safe((*cmd_hash), i, tmp, desc_node, node) {
		hash_del(&desc_node->node);
		kfree(desc_node);
	}
}

static DECLARE_HASHTABLE(klpp_gen9_blt_cmd_hash, I915_CMD_HASH_ORDER);

static const struct drm_i915_cmd_descriptor*
klpp_find_cmd_in_table(struct intel_engine_cs *engine,
		  u32 cmd_header)
{
	struct cmd_node *desc_node;
	/*
	 * Fix CVE-2019-0155
	 *  -2 lines, +5 lines
	 * Special case on gen9 blt engine and use
	 * the static hashtable in this case.
	 */
	DECLARE_HASHTABLE((*cmd_hash), I915_CMD_HASH_ORDER) = &engine->cmd_hash;
	if (klpp_is_gen9_blt(engine))
		cmd_hash = &klpp_gen9_blt_cmd_hash;

	hash_for_each_possible((*cmd_hash), desc_node, node,
			       cmd_header_key(cmd_header)) {
		const struct drm_i915_cmd_descriptor *desc = desc_node->desc;
		if (((cmd_header ^ desc->cmd.value) & desc->cmd.mask) == 0)
			return desc;
	}

	return NULL;
}

static const struct drm_i915_cmd_descriptor*
klpp_find_cmd(struct intel_engine_cs *engine,
	 u32 cmd_header,
	 const struct drm_i915_cmd_descriptor *desc,
	 struct drm_i915_cmd_descriptor *default_desc)
{
	u32 mask;

	if (((cmd_header ^ desc->cmd.value) & desc->cmd.mask) == 0)
		return desc;

	desc = klpp_find_cmd_in_table(engine, cmd_header);
	if (desc)
		return desc;

	/*
	 * Fix CVE-2019-0155
	 *  -1 line, +4 lines
	 * Special case on gen9 blt engine and use
	 * kgrp_gen9_blt_get_cmd_length_mask() in this case.
	 */
	if (!klpp_is_gen9_blt(engine))
		mask = engine->get_cmd_length_mask(cmd_header);
	else
		mask = klpp_gen9_blt_get_cmd_length_mask(cmd_header);
	if (!mask)
		return NULL;

	default_desc->cmd.value = cmd_header;
	default_desc->cmd.mask = ~0u << MIN_OPCODE_SHIFT;
	default_desc->length.mask = mask;
	default_desc->flags = CMD_DESC_SKIP;
	return default_desc;
}

static const struct drm_i915_reg_descriptor *
__find_reg(const struct drm_i915_reg_descriptor *table, int count, u32 addr)
{
	int start = 0, end = count;
	while (start < end) {
		int mid = start + (end - start) / 2;
		int ret = addr - i915_mmio_reg_offset(table[mid].addr);
		if (ret < 0)
			end = mid;
		else if (ret > 0)
			start = mid + 1;
		else
			return &table[mid];
	}
	return NULL;
}

static const struct drm_i915_reg_descriptor *
/*
 * Fix CVE-2019-0155
 *  -1 line, +1 line
 */
klpp_find_reg(const struct intel_engine_cs *engine, u32 addr)
{
	const struct drm_i915_reg_table *table = engine->reg_tables;
	int count = engine->reg_table_count;

	/*
	 * Fix CVE-2019-0155
	 *  4 lines
	 * Special case on gen9 blt engine and use
	 * the static register table in this case.
	 */
	if (klpp_is_gen9_blt(engine)) {
		table = klpp_gen9_blt_reg_tables;
		count = ARRAY_SIZE(klpp_gen9_blt_reg_tables);
	}

	for (; count > 0; ++table, --count) {
		/*
		 * Fix CVE-2019-0155
		 *  -1 line, +1 line
		 * Never search master tables.
		 */
		if (!table->master) {
			const struct drm_i915_reg_descriptor *reg;

			reg = __find_reg(table->regs, table->num_regs, addr);
			if (reg != NULL)
				return reg;
		}
	}

	return NULL;
}

static u32 *klpr_copy_batch(struct drm_i915_gem_object *dst_obj,
		       struct drm_i915_gem_object *src_obj,
		       u32 batch_start_offset,
		       u32 batch_len,
		       bool *needs_clflush_after)
{
	unsigned int src_needs_clflush;
	unsigned int dst_needs_clflush;
	void *dst, *src;
	int ret;

	ret = (*klpe_i915_gem_obj_prepare_shmem_read)(src_obj, &src_needs_clflush);
	if (ret)
		return ERR_PTR(ret);

	ret = (*klpe_i915_gem_obj_prepare_shmem_write)(dst_obj, &dst_needs_clflush);
	if (ret) {
		dst = ERR_PTR(ret);
		goto unpin_src;
	}

	dst = (*klpe_i915_gem_object_pin_map)(dst_obj, I915_MAP_FORCE_WB);
	if (IS_ERR(dst))
		goto unpin_dst;

	src = ERR_PTR(-ENODEV);
	if (src_needs_clflush &&
	    klpr_i915_can_memcpy_from_wc(NULL, batch_start_offset, 0)) {
		src = (*klpe_i915_gem_object_pin_map)(src_obj, I915_MAP_WC);
		if (!IS_ERR(src)) {
			(*klpe_i915_memcpy_from_wc)(dst,
					    src + batch_start_offset,
					    ALIGN(batch_len, 16));
			i915_gem_object_unpin_map(src_obj);
		}
	}
	if (IS_ERR(src)) {
		void *ptr;
		int offset, n;

		offset = offset_in_page(batch_start_offset);

		/* We can avoid clflushing partial cachelines before the write
		 * if we only every write full cache-lines. Since we know that
		 * both the source and destination are in multiples of
		 * PAGE_SIZE, we can simply round up to the next cacheline.
		 * We don't care about copying too much here as we only
		 * validate up to the end of the batch.
		 */
		if (dst_needs_clflush & CLFLUSH_BEFORE)
			batch_len = roundup(batch_len,
					    boot_cpu_data.x86_clflush_size);

		ptr = dst;
		for (n = batch_start_offset >> PAGE_SHIFT; batch_len; n++) {
			int len = min_t(int, batch_len, PAGE_SIZE - offset);

			src = kmap_atomic((*klpe_i915_gem_object_get_page)(src_obj, n));
			if (src_needs_clflush)
				(*klpe_drm_clflush_virt_range)(src + offset, len);
			memcpy(ptr, src + offset, len);
			kunmap_atomic(src);

			ptr += len;
			batch_len -= len;
			offset = 0;
		}
	}

	/* dst_obj is returned with vmap pinned */
	*needs_clflush_after = dst_needs_clflush & CLFLUSH_AFTER;

unpin_dst:
	i915_gem_obj_finish_shmem_access(dst_obj);
unpin_src:
	i915_gem_obj_finish_shmem_access(src_obj);
	return dst;
}

static bool klpp_check_cmd(const struct intel_engine_cs *engine,
		      const struct drm_i915_cmd_descriptor *desc,
		      /*
		       * Fix CVE-2019-0155
		       *  -2 lines, +1 line
		       */
		      const u32 *cmd, u32 length)
{
	if (desc->flags & CMD_DESC_SKIP)
		return true;

	if (desc->flags & CMD_DESC_REJECT) {
		KLPR_DRM_DEBUG_DRIVER("CMD: Rejected command: 0x%08X\n", *cmd);
		return false;
	}

	/*
	 * Fix CVE-2019-0155
	 *  -5 lines
	 * Don't reject CMD_DESC_MASTER, c.f. upstream commit
	 * 66d8aba1cd6d ("drm/i915: Remove Master tables from cmdparser").
	 */

	/*
	 * Fix CVE-2019-0155
	 *  -1 line, +2 lines
	 * Treat CMD_DESC_MASTER as CMD_DESC_REGISTER, c.f. upstream commit
	 * 66d8aba1cd6d ("drm/i915: Remove Master tables from cmdparser").
	 */
	if ((desc->flags & CMD_DESC_REGISTER) ||
	    (desc->flags & CMD_DESC_MASTER)) {
		/*
		 * Get the distance between individual register offset
		 * fields if the command can perform more than one
		 * access at a time.
		 */
		const u32 step = desc->reg.step ? desc->reg.step : length;
		u32 offset;

		for (offset = desc->reg.offset; offset < length;
		     offset += step) {
			const u32 reg_addr = cmd[offset] & desc->reg.mask;
			const struct drm_i915_reg_descriptor *reg =
				/*
				 * Fix CVE-2019-0155
				 *  -1 line, +1 line
				 */
				klpp_find_reg(engine, reg_addr);

			if (!reg) {
				KLPR_DRM_DEBUG_DRIVER("CMD: Rejected register 0x%08X in command: 0x%08X (%s)\n",
						 reg_addr, *cmd, engine->name);
				return false;
			}

			/*
			 * Check the value written to the register against the
			 * allowed mask/value pair given in the whitelist entry.
			 */
			if (reg->mask) {
				/*
				 * Fix CVE-2019-0155
				 *  -1 line, +2 lines
				 */
				if (desc->cmd.value == MI_LOAD_REGISTER_MEM ||
				    desc->cmd.value == MI_LOAD_REGISTER_MEM_GEN8) {
					KLPR_DRM_DEBUG_DRIVER("CMD: Rejected LRM to masked register 0x%08X\n",
							 reg_addr);
					return false;
				}

				if (desc->cmd.value == MI_LOAD_REGISTER_REG) {
					KLPR_DRM_DEBUG_DRIVER("CMD: Rejected LRR to masked register 0x%08X\n",
							 reg_addr);
					return false;
				}

				if (desc->cmd.value == MI_LOAD_REGISTER_IMM(1) &&
				    (offset + 2 > length ||
				     (cmd[offset + 1] & reg->mask) != reg->value)) {
					KLPR_DRM_DEBUG_DRIVER("CMD: Rejected LRI to masked register 0x%08X\n",
							 reg_addr);
					return false;
				}
			}
		}
	}

	if (desc->flags & CMD_DESC_BITMASK) {
		int i;

		for (i = 0; i < MAX_CMD_DESC_BITMASKS; i++) {
			u32 dword;

			if (desc->bits[i].mask == 0)
				break;

			if (desc->bits[i].condition_mask != 0) {
				u32 offset =
					desc->bits[i].condition_offset;
				u32 condition = cmd[offset] &
					desc->bits[i].condition_mask;

				if (condition == 0)
					continue;
			}

			if (desc->bits[i].offset >= length) {
				KLPR_DRM_DEBUG_DRIVER("CMD: Rejected command 0x%08X, too short to check bitmask (%s)\n",
						 *cmd, engine->name);
				return false;
			}

			dword = cmd[desc->bits[i].offset] &
				desc->bits[i].mask;

			if (dword != desc->bits[i].expected) {
				KLPR_DRM_DEBUG_DRIVER("CMD: Rejected command 0x%08X for bitmask 0x%08X (exp=0x%08X act=0x%08X) (%s)\n",
						 *cmd,
						 desc->bits[i].mask,
						 desc->bits[i].expected,
						 dword, engine->name);
				return false;
			}
		}
	}

	return true;
}

/*
 * Don't bother with adding shadow variables to struct
 * i915_gem_context and simply allocate a whitelist for each
 * intel_engine_cmd_parser() invocation.
 */
struct klpp_jump_whitelist
{
	unsigned long *jump_whitelist;
	uint32_t jump_whitelist_cmds;
};

static int klpp_check_bbstart(const struct i915_gem_context *ctx,
			 struct klpp_jump_whitelist *jw,
			 u32 *cmd, u32 offset, u32 length,
			 u32 batch_len,
			 u64 batch_start,
			 u64 shadow_batch_start)
{
	u64 jump_offset, jump_target;
	u32 target_cmd_offset, target_cmd_index;

	/* For igt compatibility on older platforms */
	if (KLPP_CMDPARSER_USES_GGTT(ctx->i915)) {
		KLPR_DRM_DEBUG("CMD: Rejecting BB_START for ggtt based submission\n");
		return -EACCES;
	}

	if (length != 3) {
		KLPR_DRM_DEBUG("CMD: Recursive BB_START with bad length(%u)\n",
			  length);
		return -EINVAL;
	}

	jump_target = *(u64*)(cmd+1);
	jump_offset = jump_target - batch_start;

	/*
	 * Any underflow of jump_target is guaranteed to be outside the range
	 * of a u32, so >= test catches both too large and too small
	 */
	if (jump_offset >= batch_len) {
		KLPR_DRM_DEBUG("CMD: BB_START to 0x%llx jumps out of BB\n",
			  jump_target);
		return -EINVAL;
	}

	/*
	 * This cannot overflow a u32 because we already checked jump_offset
	 * is within the BB, and the batch_len is a u32
	 */
	target_cmd_offset = lower_32_bits(jump_offset);
	target_cmd_index = target_cmd_offset / sizeof(u32);

	*(u64*)(cmd + 1) = shadow_batch_start + target_cmd_offset;

	if (target_cmd_index == offset)
		return 0;

	if (jw->jump_whitelist_cmds <= target_cmd_index) {
		KLPR_DRM_DEBUG("CMD: Rejecting BB_START - truncated whitelist array\n");
		return -EINVAL;
	} else if (!test_bit(target_cmd_index, jw->jump_whitelist)) {
		KLPR_DRM_DEBUG("CMD: BB_START to 0x%llx not a previously executed cmd\n",
			  jump_target);
		return -EINVAL;
	}

	return 0;
}

static void klpp_init_whitelist(struct i915_gem_context *ctx,
				struct klpp_jump_whitelist *jw, u32 batch_len)
{
	const u32 batch_cmds = DIV_ROUND_UP(batch_len, sizeof(u32));
	const u32 exact_size = BITS_TO_LONGS(batch_cmds);
	unsigned long *next_whitelist;

	memset(jw, 0, sizeof(*jw));

	if (KLPP_CMDPARSER_USES_GGTT(ctx->i915))
		return;

	next_whitelist = kcalloc(exact_size, sizeof(long), GFP_KERNEL);
	if (next_whitelist) {
		jw->jump_whitelist = next_whitelist;
		jw->jump_whitelist_cmds =
			exact_size * BITS_PER_BYTE * sizeof(long);
		return;
	}

	KLPR_DRM_DEBUG("CMD: Failed to extend whitelist. BB_START may be disallowed\n");

	return;
}

#define LENGTH_BIAS 2

/*
 * Fix CVE-2019-0155
 *  -6 lines, +8 lines
 */
int klpp_intel_engine_cmd_parser(struct i915_gem_context *ctx,
			    struct intel_engine_cs *engine,
			    struct drm_i915_gem_object *batch_obj,
			    u64 batch_start,
			    u32 batch_start_offset,
			    u32 batch_len,
			    struct drm_i915_gem_object *shadow_batch_obj,
			    u64 shadow_batch_start)
{
	/*
	 * Fix CVE-2019-0155
	 *  -1 line, +1 line
	 */
	u32 *cmd, *batch_end, offset = 0;
	struct drm_i915_cmd_descriptor default_desc = noop_desc;
	const struct drm_i915_cmd_descriptor *desc = &default_desc;
	bool needs_clflush_after = false;
	int ret = 0;
	/*
	 *Fix CVE-2019-0155
	 *  +1 line
	 */
	struct klpp_jump_whitelist jw;

	cmd = klpr_copy_batch(shadow_batch_obj, batch_obj,
			 batch_start_offset, batch_len,
			 &needs_clflush_after);
	if (IS_ERR(cmd)) {
		KLPR_DRM_DEBUG_DRIVER("CMD: Failed to copy batch\n");
		return PTR_ERR(cmd);
	}

	/*
	 * Fix CVE-2019-0155
	 *  +1 line
	 */
	klpp_init_whitelist(ctx, &jw, batch_len);

	/*
	 * We use the batch length as size because the shadow object is as
	 * large or larger and copy_batch() will write MI_NOPs to the extra
	 * space. Parsing should be faster in some cases this way.
	 */
	batch_end = cmd + (batch_len / sizeof(*batch_end));
	do {
		u32 length;

		/*
		 * Fix CVE-2019-0155
		 *  -8 lines, +2 lines
		 */
		if (*cmd == MI_BATCH_BUFFER_END)
			break;

		desc = klpp_find_cmd(engine, *cmd, desc, &default_desc);
		if (!desc) {
			KLPR_DRM_DEBUG_DRIVER("CMD: Unrecognized command: 0x%08X\n",
					 *cmd);
			ret = -EINVAL;
			/*
			 * Fix CVE-2019-0155
			 *  -1 line, +1 line
			 */
			goto err;
		}

		/*
		 * Fix CVE-2019-0155
		 *  -9 lines
		 */

		if (desc->flags & CMD_DESC_FIXED)
			length = desc->length.fixed;
		else
			length = ((*cmd & desc->length.mask) + LENGTH_BIAS);

		if ((batch_end - cmd) < length) {
			KLPR_DRM_DEBUG_DRIVER("CMD: Command length exceeds batch length: 0x%08X length=%u batchlen=%td\n",
					 *cmd,
					 length,
					 batch_end - cmd);
			ret = -EINVAL;
			/*
			 * Fix CVE-2019-0155
			 *  -1 line, +1 line
			 */
			goto err;
		}

		/*
		 * Fix CVE-2019-0155
		 *  -1 line, +1 line
		 */
		if (!klpp_check_cmd(engine, desc, cmd, length)) {
			ret = -EACCES;
			/*
			 * Fix CVE-2019-0155
			 *  -1 line, +1 line
			 */
			goto err;
		}

		/*
		 * Fix CVE-2019-0155
		 *  +13 lines
		 */
		if (desc->cmd.value == MI_BATCH_BUFFER_START ||
		    desc->cmd.value == MI_BATCH_BUFFER_START_GEN8) {
			ret = klpp_check_bbstart(ctx, &jw, cmd, offset, length,
					    batch_len, batch_start,
					    shadow_batch_start);

			if (ret)
				goto err;
			break;
		}

		if (jw.jump_whitelist_cmds > offset)
			set_bit(offset, jw.jump_whitelist);

		cmd += length;
		/*
		 * Fix CVE-2019-0155
		 *  +1 line
		 */
		offset += length;
		if  (cmd >= batch_end) {
			KLPR_DRM_DEBUG_DRIVER("CMD: Got to the end of the buffer w/o a BBE cmd!\n");
			ret = -EINVAL;
			/*
			 * Fix CVE-2019-0155
			 *  -1 line, +1 line
			 */
			goto err;
		}
	} while (1);

	/*
	 * Fix CVE-2019-0155
	 *  +7 lines
	 */
	if (needs_clflush_after) {
		void *ptr = page_mask_bits(shadow_batch_obj->mm.mapping);

		(*klpe_drm_clflush_virt_range)(ptr, (void *)(cmd + 1) - ptr);
	}

err:
	/*
	 * Fix CVE-2019-0155
	 *  +1 line
	 */
	kfree(jw.jump_whitelist);
	i915_gem_object_unpin_map(shadow_batch_obj);
	return ret;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_clflush_virt_range", (void *)&klpe_drm_clflush_virt_range,
	  "drm" },
	{ "i915_gem_object_get_page", (void *)&klpe_i915_gem_object_get_page,
	  "i915" },
	{ "i915_gem_object_pin_map", (void *)&klpe_i915_gem_object_pin_map,
	  "i915" },
	{ "i915_gem_obj_prepare_shmem_read",
	  (void *)&klpe_i915_gem_obj_prepare_shmem_read, "i915" },
	{ "i915_gem_obj_prepare_shmem_write",
	  (void *)&klpe_i915_gem_obj_prepare_shmem_write, "i915" },
	{ "i915_memcpy_from_wc", (void *)&klpe_i915_memcpy_from_wc, "i915" },
};

int klp_bsc1173663_cmd_parser_resolve_kallsyms(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

int klp_bsc1173663_cmd_parser_init(void)
{
	return klpp_init_hash_table(&klpp_gen9_blt_cmd_hash,
				    klpp_gen9_blt_cmd_table,
				    ARRAY_SIZE(klpp_gen9_blt_cmd_table));
}

void klp_bsc1173663_cmd_parser_cleanup(void)
{
	klpp_fini_hash_table(&klpp_gen9_blt_cmd_hash);
}

#endif
