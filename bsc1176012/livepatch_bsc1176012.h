#ifndef _LIVEPATCH_BSC1176012_H
#define _LIVEPATCH_BSC1176012_H

int livepatch_bsc1176012_init(void);
void livepatch_bsc1176012_cleanup(void);


int
klpp_futex_wake(u32 __user *uaddr, unsigned int flags, int nr_wake, u32 bitset);

int klpp_futex_wait(u32 __user *uaddr, unsigned int flags, u32 val,
		      ktime_t *abs_time, u32 bitset);

long klpp_do_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
		u32 __user *uaddr2, u32 val2, u32 val3);

#endif /* _LIVEPATCH_BSC1176012_H */
