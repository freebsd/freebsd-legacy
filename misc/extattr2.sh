#!/bin/sh

#
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2018 Dell EMC Isilon
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

# [Bug 230962] Kernel panic when writing extended attributes with soft updates
# enabled.
# "panic: softdep_deallocate_dependencies: dangling deps" seen:
# https://people.freebsd.org/~pho/stress/log/kostik1121.txt

[ `id -u ` -ne 0 ] && echo "Must be root!" && exit 1

. ../default.cfg
[ "`sysctl -in kern.features.ufs_extattr`" != "1" ] && exit 0
[ -z "`which setfacl`" ] && exit 0

here=`pwd`
mount | grep "$mntpoint" | grep -q md${mdstart}$part && umount $mntpoint
mdconfig -l | grep -q md$mdstart &&  mdconfig -d -u $mdstart

mdconfig -a -t swap -s 2g -u $mdstart
bsdlabel -w md$mdstart auto

newfs $newfs_flags md${mdstart}$part > /dev/null
mount /dev/md${mdstart}$part $mntpoint

mkdir -p $mntpoint/.attribute/system
cd $mntpoint/.attribute/system

extattrctl initattr -p . 388 posix1e.acl_access
extattrctl initattr -p . 388 posix1e.acl_default
cd /
umount $mntpoint
tunefs -a enable /dev/md${mdstart}$part
mount /dev/md${mdstart}$part $mntpoint
mount | grep md${mdstart}$part

export runRUNTIME=10m
export RUNDIR=$mntpoint/stressX
if [ `jot -r 1 0 1` -eq 1 ]; then
	set `df -ik $mntpoint | tail -1 | awk '{print $4,$7}'`
	export KBLOCKS=$(($1 / 2))
	export INODES=$(($2 / 2))
fi

mkdir -p $RUNDIR
chmod 0777 $RUNDIR
setfacl -b $RUNDIR
setfacl -m user:$testuser:rwx,group:$testuser:rwx $RUNDIR
su $testuser -c "cd $here/..; ./run.sh marcus.cfg" &

sleep 5
while pgrep -U$testuser -q -f run.sh; do
	find $RUNDIR | xargs -P0 -J% setfacl -m user:$testuser:rwx,group:$testuser:rwx % > /dev/null 2>&1
done
wait

s=0
for i in `jot 6`; do
	mount | grep -q "on $mntpoint " || break
	umount $mntpoint && break || sleep 10
	[ $i -eq 6 ] &&
	    { echo FAIL; fstat -mf $mntpoint; exit 1; }
done
checkfs /dev/md${mdstart}$part || s=1
mdconfig -d -u $mdstart || s=2
exit $s
