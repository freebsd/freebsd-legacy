#!/bin/sh

# Test scenario submitted by Mark Johnston <markj@freebsd.org>

# "Fatal trap 18: integer divide fault while in kernel mode" seen.
# Reported by syzkaller
# Fixed by r353010

cat > /tmp/fcntl3.c <<EOF
#include <err.h>
#include <fcntl.h>
#include <unistd.h>

int
main(void)
{

	if (fcntl(STDIN_FILENO, F_RDAHEAD) != 0)
		err(1, "fcntl");
	return (0);
}
EOF
cc -o /tmp/fcntl3 -Wall -Wextra -O2 /tmp/fcntl3.c || exit 1

echo "Expect: fcntl3: fcntl: Inappropriate ioctl for device"
/tmp/fcntl3

rm -f /tmp/fcntl3 /tmp/fcntl3.c
exit 0
