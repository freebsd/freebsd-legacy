#!/bin/sh

# "panic: pmap_demote_pde: page table page for a wired mapping
# is missing" seen.
# Test scenario by Mark Johnston <markj@freebsd.org>

# Fixed by r345382

# $FreeBSD$

. ../default.cfg

cd /tmp
cat > mprotect.c <<EOF
#include <sys/mman.h>

#include <err.h>
#include <stdlib.h>

int
main(void)
{
	char *addr, c;
	size_t i, len;

	len = 2 * 1024 * 1024;
	addr = mmap(NULL, 2 * 1024 * 1024, PROT_READ,
	    MAP_ANON | MAP_ALIGNED_SUPER, -1, 0);
	if (addr == MAP_FAILED)
		err(1, "mmap");
	if (mlock(addr, len) != 0) /* hopefully this gets a superpage */
		err(1, "mlock");
	if (mprotect(addr, len, PROT_NONE) != 0)
		err(1, "mprotect");
	if (mprotect(addr, len, PROT_READ) != 0)
		err(1, "mprotect");
	for (i = 0; i < len; i++) /* preemptive superpage mapping */
		c = *(volatile char *)(addr + i);
	if (mprotect(addr, 4096, PROT_NONE) != 0) /* trigger demotion */
		err(1, "mprotect");
	if (munlock(addr, len) != 0)
		err(1, "munlock");

	return (0);
}
EOF
mycc -o mprotect -Wall -Wextra -O2 mprotect.c || exit 1

./mprotect; s=$?

rm mprotect.c mprotect
exit $s
