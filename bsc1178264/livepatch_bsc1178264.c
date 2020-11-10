/*
 * livepatch_bsc1178264
 *
 * Fix for CVE-2017-1000405, bsc#1178264
 *
 *  Upstream commit:
 *  a8f97366452e ("mm, thp: Do not make page table dirty unconditionally in
 *                 touch_p[mu]d()")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  f186ddee48e348e8d7f4fe9a134c03c39c9be69b
 *
 *  SLE15-SP2 commit:
 *  not affected
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

/* klp-ccp: from mm/huge_memory.c */
#define pr_fmt(fmt) "huge_memory" ": " fmt

#include <linux/mm.h>


#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1178264.h"
#include "../kallsyms_relocs.h"

#if defined(__powerpc64__)

static struct page *(*klpe_pmd_page)(pmd_t pmd);
#define klpr_pmd_page (*klpe_pmd_page)

static void (*klpe_update_mmu_cache_pmd)(struct vm_area_struct *vma, unsigned long addr,
					pmd_t *pmd);
#define klpr_update_mmu_cache_pmd (*klpe_update_mmu_cache_pmd)

#else

#define klpr_pmd_page pmd_page
#define klpr_update_mmu_cache_pmd update_mmu_cache_pmd

#endif



/* klp-ccp: from arch/x86/include/asm/pgtable.h */
/* klp-ccp: from arch/powerpc/include/asm/book3s/64/pgtable.h */
static int (*klpe_pmdp_set_access_flags)(struct vm_area_struct *vma,
				 unsigned long address, pmd_t *pmdp,
				 pmd_t entry, int dirty);

/* klp-ccp: from arch/x86/include/asm/pgtable.h */
#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
static int (*klpe_pudp_set_access_flags)(struct vm_area_struct *vma,
				 unsigned long address, pud_t *pudp,
				 pud_t entry, int dirty);
#endif

/* klp-ccp: from include/linux/huge_mm.h */
struct page *klpp_follow_trans_huge_pmd(struct vm_area_struct *vma,
					  unsigned long addr,
					  pmd_t *pmd,
					  unsigned int flags);

struct page *klpp_follow_devmap_pmd(struct vm_area_struct *vma, unsigned long addr,
		pmd_t *pmd, int flags);
struct page *klpp_follow_devmap_pud(struct vm_area_struct *vma, unsigned long addr,
		pud_t *pud, int flags);

static struct page *(*klpe_huge_zero_page);

static inline bool klpr_is_huge_zero_page(struct page *page)
{
	return READ_ONCE((*klpe_huge_zero_page)) == page;
}

static inline bool klpr_is_huge_zero_pmd(pmd_t pmd)
{
	return klpr_is_huge_zero_page(klpr_pmd_page(pmd));
}

/* klp-ccp: from mm/huge_memory.c */
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>

/* klp-ccp: from include/linux/swap.h */
static void (*klpe_lru_add_drain)(void);

/* klp-ccp: from mm/huge_memory.c */
#include <linux/swap.h>
#include <linux/shrinker.h>
#include <linux/dax.h>
#include <linux/memremap.h>
#include <linux/pagemap.h>
#include <linux/numa.h>
#include <asm/pgalloc.h>

/* klp-ccp: from mm/internal.h */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/tracepoint-defs.h>

static void (*klpe_mlock_vma_page)(struct page *page);

/* klp-ccp: from mm/huge_memory.c */
static struct page *(*klpe_huge_zero_page) __read_mostly;

static void klpp_touch_pmd(struct vm_area_struct *vma, unsigned long addr,
		/*
		 * Fix CVE-2017-1000405
		 *  -1 line, +1 line
		 */
		pmd_t *pmd, int flags)
{
	pmd_t _pmd;

	/*
	 * Fix CVE-2017-1000405
	 *  -8 lines, +3 lines
	 */
	_pmd = pmd_mkyoung(*pmd);
	if (flags & FOLL_WRITE)
		_pmd = pmd_mkdirty(_pmd);
	if ((*klpe_pmdp_set_access_flags)(vma, addr & HPAGE_PMD_MASK,
				/*
				 * Fix CVE-2017-1000405
				 *  -1 line, +1 line
				 */
				pmd, _pmd, flags & FOLL_WRITE))
		klpr_update_mmu_cache_pmd(vma, addr, pmd);
}

struct page *klpp_follow_devmap_pmd(struct vm_area_struct *vma, unsigned long addr,
		pmd_t *pmd, int flags)
{
	unsigned long pfn = pmd_pfn(*pmd);
	struct mm_struct *mm = vma->vm_mm;
	struct dev_pagemap *pgmap;
	struct page *page;

	assert_spin_locked(pmd_lockptr(mm, pmd));

	/*
	 * When we COW a devmap PMD entry, we split it into PTEs, so we should
	 * not be in this function with `flags & FOLL_COW` set.
	 */
	WARN_ONCE(flags & FOLL_COW, "mm: In follow_devmap_pmd with FOLL_COW set");

	if (flags & FOLL_WRITE && !pmd_write(*pmd))
		return NULL;

	if (pmd_present(*pmd) && pmd_devmap(*pmd))
		/* pass */;
	else
		return NULL;

	if (flags & FOLL_TOUCH)
		/*
		 * Fix CVE-2017-1000405
		 *  -1 line, +1 line
		 */
		klpp_touch_pmd(vma, addr, pmd, flags);

	/*
	 * device mapped pages can only be returned if the
	 * caller will manage the page reference count.
	 */
	if (!(flags & FOLL_GET))
		return ERR_PTR(-EEXIST);

	pfn += (addr & ~PMD_MASK) >> PAGE_SHIFT;
	pgmap = get_dev_pagemap(pfn, NULL);
	if (!pgmap)
		return ERR_PTR(-EFAULT);
	page = pfn_to_page(pfn);
	get_page(page);
	put_dev_pagemap(pgmap);

	return page;
}

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
static void klpp_touch_pud(struct vm_area_struct *vma, unsigned long addr,
		/*
		 * Fix CVE-2017-1000405
		 *  -1 line, +1 line
		 */
		pud_t *pud, int flags)
{
	pud_t _pud;

	/*
	 * Fix CVE-2017-1000405
	 *  -8 line, +3 lines
	 */
	_pud = pud_mkyoung(*pud);
	if (flags & FOLL_WRITE)
		_pud = pud_mkdirty(_pud);
	if ((*klpe_pudp_set_access_flags)(vma, addr & HPAGE_PUD_MASK,
				/*
				 * Fix CVE-2017-1000405
				 *  -1 line, +1 line
				 */
				pud, _pud, flags & FOLL_WRITE))
		update_mmu_cache_pud(vma, addr, pud);
}

struct page *klpp_follow_devmap_pud(struct vm_area_struct *vma, unsigned long addr,
		pud_t *pud, int flags)
{
	unsigned long pfn = pud_pfn(*pud);
	struct mm_struct *mm = vma->vm_mm;
	struct dev_pagemap *pgmap;
	struct page *page;

	assert_spin_locked(pud_lockptr(mm, pud));

	if (flags & FOLL_WRITE && !pud_write(*pud))
		return NULL;

	if (pud_present(*pud) && pud_devmap(*pud))
		/* pass */;
	else
		return NULL;

	if (flags & FOLL_TOUCH)
		/*
		 * Fix CVE-2017-1000405
		 *  -1 line, +1 line
		 */
		klpp_touch_pud(vma, addr, pud, flags);

	/*
	 * device mapped pages can only be returned if the
	 * caller will manage the page reference count.
	 */
	if (!(flags & FOLL_GET))
		return ERR_PTR(-EEXIST);

	pfn += (addr & ~PUD_MASK) >> PAGE_SHIFT;
	pgmap = get_dev_pagemap(pfn, NULL);
	if (!pgmap)
		return ERR_PTR(-EFAULT);
	page = pfn_to_page(pfn);
	get_page(page);
	put_dev_pagemap(pgmap);

	return page;
}
#endif /* CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD */

static inline bool can_follow_write_pmd(pmd_t pmd, unsigned int flags)
{
	return pmd_write(pmd) ||
	       ((flags & FOLL_FORCE) && (flags & FOLL_COW) && pmd_dirty(pmd));
}

struct page *klpp_follow_trans_huge_pmd(struct vm_area_struct *vma,
				   unsigned long addr,
				   pmd_t *pmd,
				   unsigned int flags)
{
	struct mm_struct *mm = vma->vm_mm;
	struct page *page = NULL;

	assert_spin_locked(pmd_lockptr(mm, pmd));

	if (flags & FOLL_WRITE && !can_follow_write_pmd(*pmd, flags))
		goto out;

	/* Avoid dumping huge zero page */
	if ((flags & FOLL_DUMP) && klpr_is_huge_zero_pmd(*pmd))
		return ERR_PTR(-EFAULT);

	/* Full NUMA hinting faults to serialise migration in fault paths */
	if ((flags & FOLL_NUMA) && pmd_protnone(*pmd))
		goto out;

	page = klpr_pmd_page(*pmd);
	VM_BUG_ON_PAGE(!PageHead(page) && !is_zone_device_page(page), page);
	if (flags & FOLL_TOUCH)
		/*
		 * Fix CVE-2017-1000405
		 *  -1 line, +1 line
		 */
		klpp_touch_pmd(vma, addr, pmd, flags);
	if ((flags & FOLL_MLOCK) && (vma->vm_flags & VM_LOCKED)) {
		/*
		 * We don't mlock() pte-mapped THPs. This way we can avoid
		 * leaking mlocked pages into non-VM_LOCKED VMAs.
		 *
		 * For anon THP:
		 *
		 * In most cases the pmd is the only mapping of the page as we
		 * break COW for the mlock() -- see gup_flags |= FOLL_WRITE for
		 * writable private mappings in populate_vma_page_range().
		 *
		 * The only scenario when we have the page shared here is if we
		 * mlocking read-only mapping shared over fork(). We skip
		 * mlocking such pages.
		 *
		 * For file THP:
		 *
		 * We can expect PageDoubleMap() to be stable under page lock:
		 * for file pages we set it in page_add_file_rmap(), which
		 * requires page to be locked.
		 */

		if (PageAnon(page) && compound_mapcount(page) != 1)
			goto skip_mlock;
		if (PageDoubleMap(page) || !page->mapping)
			goto skip_mlock;
		if (!trylock_page(page))
			goto skip_mlock;
		(*klpe_lru_add_drain)();
		if (page->mapping && !PageDoubleMap(page))
			(*klpe_mlock_vma_page)(page);
		unlock_page(page);
	}
skip_mlock:
	page += (addr & ~HPAGE_PMD_MASK) >> PAGE_SHIFT;
	VM_BUG_ON_PAGE(!PageCompound(page) && !is_zone_device_page(page), page);
	if (flags & FOLL_GET)
		get_page(page);

out:
	return page;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
#if defined(__powerpc64__)
	{ "pmd_page", (void *)&klpe_pmd_page },
	{ "update_mmu_cache_pmd", (void *)&klpe_update_mmu_cache_pmd },
#endif
	{ "huge_zero_page", (void *)&klpe_huge_zero_page },
	{ "pmdp_set_access_flags", (void *)&klpe_pmdp_set_access_flags },
#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
	{ "pudp_set_access_flags", (void *)&klpe_pudp_set_access_flags },
#endif
	{ "mlock_vma_page", (void *)&klpe_mlock_vma_page },
	{ "lru_add_drain", (void *)&klpe_lru_add_drain },
};

int livepatch_bsc1178264_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
