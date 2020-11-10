#ifndef _LIVEPATCH_BSC1178264_H
#define _LIVEPATCH_BSC1178264_H

int livepatch_bsc1178264_init(void);
static inline void livepatch_bsc1178264_cleanup(void) {}


#include <linux/mm.h>

struct page *klpp_follow_trans_huge_pmd(struct vm_area_struct *vma,
					  unsigned long addr,
					  pmd_t *pmd,
					  unsigned int flags);

struct page *klpp_follow_devmap_pmd(struct vm_area_struct *vma, unsigned long addr,
		pmd_t *pmd, int flags);
struct page *klpp_follow_devmap_pud(struct vm_area_struct *vma, unsigned long addr,
		pud_t *pud, int flags);


#endif /* _LIVEPATCH_BSC1178264_H */
