#ifndef __COMPEL_SYSCALL_H__
#define __COMPEL_SYSCALL_H__
#define __NR(syscall, compat)   \
	({                      \
		(void)compat;   \
		__NR_##syscall; \
	})
#endif