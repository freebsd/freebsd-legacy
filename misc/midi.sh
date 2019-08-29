#!/bin/sh

# Test scenario by Mark Johnston <markj@freebsd.org>

# 'panic: vm_fault_hold: fault on nofault entry, addr: 0x33522000' seen.
# Fixed by 351262

# $FreeBSD$

cat > /tmp/midi.c <<EOF
#include <err.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

#define NTHREADS	16

static _Atomic(int) threads;
static int fd;

static void *
t(void *data __unused)
{
	char buf[4096];
	ssize_t n;
	off_t off;

	(void)atomic_fetch_add(&threads, 1);
	while (atomic_load(&threads) != NTHREADS)
		;

	for (;;) {
		arc4random_buf(&off, sizeof(off));
		if ((n = pread(fd, buf, sizeof(buf), off)) >= 0)
			write(STDOUT_FILENO, buf, n);
	}

	return (NULL);
}

int
main(void)
{
	pthread_t tid[NTHREADS];
	int error, i;

	fd = open("/dev/midistat", O_RDONLY);
	if (fd < 0)
		err(1, "open");

	for (i = 0; i < NTHREADS; i++)
		if ((error = pthread_create(&tid[i], NULL, t, NULL)) != 0)
			errc(1, error, "pthread_create");
	for (i = 0; i < NTHREADS; i++)
		if ((error = pthread_join(tid[i], NULL)) != 0)
			errc(1, error, "pthread_join");

	return (0);
}
EOF
cc -o /tmp/midi -Wall -Wextra -O2 /tmp/midi.c -lpthread

start=`date +%s`
while [ $((`date +%s` - start)) -lt 120 ]; do
	timeout 10 /tmp/midi | strings | head -20
done

rm -f /tmp/midi /tmp/midi.c /tmp/midi.core
exit 0
