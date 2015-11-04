#!/bin/sh

#
# Copyright (c) 2009 Peter Holm <pho@FreeBSD.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$
#

# Parallel mount / umount and snapshots. No problems seen.

[ `id -u ` -ne 0 ] && echo "Must be root!" && exit 1
[ $((`sysctl -n hw.usermem` / 1024 / 1024 / 1024)) -le 3 ] && exit 0

. ../default.cfg

kldstat -v | grep -q zfs.ko  || { kldload zfs.ko; loaded=1; }

u1=$mdstart
u2=$((u1 + 1))
u3=$((u2 + 1))

mdconfig -l | grep -q md${u1} && mdconfig -d -u $u1
mdconfig -l | grep -q md${u2} && mdconfig -d -u $u2
mdconfig -l | grep -q md${u3} && mdconfig -d -u $u3

mdconfig -s 512m -u $u1
mdconfig -s 512m -u $u2
mdconfig -s 512m -u $u3

[ -d /tank ] && rm -rf /tank
zpool create tank raidz md$u1 md$u2 md$u3
zfs create tank/test

while true; do
	zfs umount tank/test
	zfs mount tank/test
done &

for i in `jot 5000`; do
	touch /tank/test/f$i
	zfs snapshot tank/test@$i
	if [ $i -gt 5 ]; then
		zfs destroy tank/test@$((i - 5))
	fi
done
kill $!
zfs destroy -r tank
zpool destroy tank

mdconfig -d -u $u1
mdconfig -d -u $u2
mdconfig -d -u $u3
[ -n "$loaded" ] && kldunload zfs.ko
