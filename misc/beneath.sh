#!/bin/sh

# Test of open(2) with the O_BENEATH flag.
# Test scenario by kib@

# userret: returning with the following locks held:
# shared lockmgr ufs (ufs) r = 0 (0xfffff804ec0d2a48) locked @
# kern/vfs_subr.c:2590 seen in WiP code:
# https://people.freebsd.org/~pho/stress/log/kostik1126.txt

# $FreeBSD

#. ../default.cfg

top=/tmp/beneath.d
mkdir -p $top
cat > $top/beneath.c <<EOF
/* $Id: beneath.c,v 1.1 2018/10/13 16:53:02 kostik Exp kostik $ */

#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef O_BENEATH
#define	O_BENEATH	0x00400000	/* Fail if not under cwd */
#define	AT_BENEATH		0x1000	/* Fail if not under dirfd */
#endif

int
main(int argc, char *argv[])
{
	struct stat st;
	char *name;
	int error, fd, i;

	for (i = 1; i < argc; i++) {
		name = argv[i];
		fd = open(name, O_RDONLY | O_BENEATH);
		if (fd == -1) {
			fprintf(stderr, "open(\"%s\") failed, error %d %s\n",
			    name, errno, strerror(errno));
		} else {
			fprintf(stderr, "open(\"%s\") succeeded\n", name);
			close(fd);
		}
		error = fstatat(AT_FDCWD, name, &st, AT_BENEATH);
		if (error == -1){
			fprintf(stderr, "stat(\"%s\") failed, error %d %s\n",
			    name, errno, strerror(errno));
		} else {
			fprintf(stderr, "stat(\"%s\") succeeded\n", name);
		}
	}
}
EOF
cc -o $top/beneath -Wall -Wextra $top/beneath.c || exit 1
rm $top/beneath.c

# Test with two directories as arguments:
cd $top
mkdir -p a/b
./beneath a/b
./beneath $top/a/b
touch $top/a/c
./beneath a/c
./beneath $top/a/c
./beneath a/d
./beneath $top/a/d

# CWD is still $top for this test
top2=/var/tmp/beneath.d
mkdir -p $top2
mkdir -p $top2/a/b
./beneath $top2/a/b > /dev/null 2>&1

touch $top2/a/c
./beneath $top2/a/c > /dev/null 2>&1

# Other CWDs
(cd /etc; find . | xargs $top/beneath) > /dev/null 2>&1
(cd /var; find . | xargs $top/beneath) > /dev/null 2>&1

rm -rf $top $top2
exit 0
