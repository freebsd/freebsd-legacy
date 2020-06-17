#!/bin/sh

#
# Copyright (c) 2008-2009, 2012-13 Peter Holm <pho@FreeBSD.org>
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

# Run all the scripts in stress2/misc, except these known problems:

# Start of list	Known problems						Seen

# altbufferflushes.sh snapshots + disk full == know problem		20130617
# backingstore.sh
#		g_vfs_done():md6a[WRITE(offset=...)]error = 28		20111220
# backingstore2.sh
#		panic: 43 vncache entries remaining			20111220
# backingstore3.sh
#		g_vfs_done():md6a[WRITE(offset=...)]error = 28		20111230
# collapse.sh	panic: freeing mapped page 0xfffffe0028ed1d50		20200106
# dd.sh		CAM stuck in vmwait					20200116
# devfs4.sh	WiP							20181031
# force.sh	WiP							20200303
# force2.sh	WiP							20200303
# force3.sh	WiP							20200303
# force4.sh	Known issue						20200303
# force5.sh	WiP							20200303
# fsync.sh	panic: Journal overflow					20190208
# fuse.sh	Memory corruption seen in log file kostik734.txt	20141114
# fuse2.sh	Deadlock seen						20121129
# fuse3.sh	Deadlock seen						20141120
# getrandom2.sh	Known DoS issue						20200302
# gjournal.sh	panic: Journal overflow					20190626
# gjournal2.sh	panic: Journal overflow					20180125
# gjournal3.sh	panic: Bio not on queue					20171225
# gjournal4.sh	CAM stuck in vmwait					20180517
# gnop7.sh	WiP							20190820
# gpt.sh	Page fault seen						20190913
# graid1_4.sh	umount stuck in mntref r338639				20180921
# graid1_8.sh	Known issue						20170909
# graid1_9.sh	panic: Bad effnlink					20180212
# kevent13.sh	panic: mutex pipe mutex not owned at sys_pipe.c:1769	20190208
# lockf5.sh	Spinning threads seen					20160718
# ifconfig.sh	WiP							20190211
# ifconfig2.sh	WiP							20190211
# maxvnodes.sh	Only supposed to work in single user mode		20190412
# maxvnodes2.sh	Only supposed to work in single user mode		20190412
# memguard.sh	Waiting for fix commit
# memguard2.sh	Waiting for fix commit
# memguard3.sh	Waiting for fix commit
# mlockall2.sh	Unrecoverable OOM killing seen				20190203
# newfs4.sh	watchdog fired. newbuf					20190225
# nfs10.sh	Double fault						20151013
# nfs13.sh	mount_nfs hangs in mntref				20191007
# nfs16.sh	panic: Failed to register NFS lock locally - error=11	20160608
# oom2.sh	Hang in pfault						20180324
# overcommit2.sh
#		CAM stuck in vmwait seen				20200112
# pfl3.sh	panic: handle_written_inodeblock: live inodedep		20190211
# pageout.sh	panic: handle_written_filepage: not started		20190218
# quota10.sh	people.freebsd.org/~pho/stress/log/quota10-2.txt	20200525
# quota2.sh	panic: dqflush: stray dquot				20120221
# quota3.sh	panic: softdep_deallocate_dependencies: unrecovered ...	20111222
# quota6.sh	panic: softdep_deallocate_dependencies: unrecovered ...	20130206
# quota7.sh	panic: dqflush: stray dquot				20120221
# rename14.sh	mark136.txt						20200525
# sctp.sh	WiP							20200307
# sctp2.sh	panic: soclose: SS_NOFDREF on enter			20200307
# sctp3.sh	WiP							20190809
# sendfile25.sh	WiP							20200611
# signal.sh	Timing issues. Needs fixing				20171116
# snap4.sh	panic: snapacct_ufs2: bad block				20181014
# snap6.sh	panic: softdep_deallocate_dependencies: unrecovered ...	20130630
# snap8.sh	panic: softdep_deallocate_dependencies: unrecovered ...	20120630
# snap9.sh	panic: handle_written_filepage: not started		20170722
# suj34.sh	Various hangs and panics (SUJ + NULLFS issue)		20131210
# swap4.sh	WiP							20171208
# swapoff2.sh	swap_pager_force_pagein: read from swap failed		20171223
# systrace.sh	WiP							20200227
# systrace2.sh	WiP							20200227
# syzkaller11.sh	WiP						20200419
# syzkaller13.sh	WiP						20200607
# syzkaller15.sh	WiP						20200617
# ucom.sh	Stuck in tail -F					20180129
# umountf7.sh	panic: handle_written_inodeblock: live inodedep ...	20190219
# umountf9.sh	panic: handle_written_inodeblock: live inodedep ...	20170221
# unionfs.sh	insmntque: non-locked vp: xx is not exclusive locked...	20130909
# unionfs2.sh	insmntque: mp-safe fs and non-locked vp is not ...	20111219
# unionfs3.sh	insmntque: mp-safe fs and non-locked vp is not ...	20111216
# zfs11.sh	Deadlock WiP						20200513

# Test not to run for other reasons:

# fuzz.sh	A know issue
# marcus3.sh	OK, but runs for a long time
# statfs.sh	Not very interesting
# vunref.sh	No problems ever seen
# vunref2.sh	No problems ever seen

# Snapshots has been disabled on SU+J
# suj15.sh
# suj16.sh
# suj19.sh
# suj20.sh
# suj21.sh
# suj22.sh
# suj24.sh
# suj25.sh
# suj26.sh
# suj27.sh
# suj28.sh

# Exclude NFS loopback tests
# nfs2.sh	panic: wrong diroffset					20140219
# nfs5.sh
# nfs6.sh
# nfs11.sh	vmwait deadlock						20151004
# nullfs8.sh
# tmpfs18.sh	mntref hang seen					20191019

# End of list

# Suspects:
# ffs_syncvnode2.sh
#		Memory modified after free. ... used by inodedep	20111224

[ `id -u ` -ne 0 ] && echo "Must be root!" && exit 1

# Log files:
sdir=/tmp/stress2.d
mkdir -p $sdir
allfaillog=$sdir/fail		# Tests that failed
alllast=$sdir/last		# Last test run
alllist=$sdir/list		# -o list
alllog=$sdir/log		# Tests run
alloutput=$sdir/output		# Output from current test
allexcess=$sdir/excessive	# Tests with excessive runtime
allelapsed=$sdir/elapsed	# Test runtime
loops=0				# Times to run the tests
rev=`uname -a | awk '{print $7}' | sed 's/://'`
rev="`uname -a | sed 's#.*/compile/##; s/ .*//'` $rev"

args=`getopt acl:m:no "$@"`
[ $? -ne 0 ] &&
    echo "Usage $0 [-a] [-c] [-l <val>] [-m <min.>] [-n] [-o] [tests]" &&
    exit 1
set -- $args
for i; do
	case "$i" in
	-a)	all=1		# Run all tests
		echo "Note: including known problem tests."
		shift
		;;
	-c)	rm -f $alllast	# Clear last know test
		rm -f $alllist
		shift
		;;
	-l)	loops=$2	# Number of time to run
		shift; shift
		;;
	-m)	minutes=$(($2 * 60))	# Run for minutes
		shift; shift
		;;
	-n)	noshuffle=1	# Do not shuffle the list of tests
		shift		# Resume test after last test
		;;
	-o)	loops=1		# Only run once
		shift
		;;
	--)
		shift
		break
		;;
	esac
done

# Sanity checks
. ../default.cfg
minspace=$((1024 * 1024)) # in k
[ -d `dirname "$diskimage"` ] ||
    { echo "diskimage dir: $diskimage not found"; exit 1; }
[ `df -k $(dirname $diskimage) | tail -1 | awk '{print $4'}` -lt \
    $minspace ] &&
    echo "Warn: Not enough disk space on `dirname $diskimage` " \
	"for \$diskimage"
[ ! -d $(dirname $RUNDIR) ] &&
    echo "No such \$RUNDIR \"`dirname $RUNDIR`\"" &&
    exit 1
[ `sysctl -n hw.physmem` -le $((3 * 1024 * 1024 * 1024)) ] &&
	echo "Warn: Small RAM size for stress tests `sysctl -n hw.physmem`"
[ `df -k $(dirname $RUNDIR) | tail -1 | awk '{print $4'}` -lt \
    $minspace ] &&
    echo "Warn: Not enough disk space on `dirname $RUNDIR` for \$RUNDIR"
id $testuser > /dev/null 2>&1 ||
    { echo "\$testuser \"$testuser\" not found."; exit 1; }
probe=`dirname $RUNDIR`/probe
su $testuser -c "touch $probe" > /dev/null 2>&1
[ -f $probe ] && rm $probe ||
    { echo "No write access to `dirname $RUNDIR`."; exit 1; }
[ `swapinfo | wc -l` -eq 1 ] &&
    echo "Consider adding a swap disk. Many tests rely on this."
mount | grep -wq $mntpoint &&
    echo "\$mntpoint ($mntpoint) is already in use" && exit 1
[ -x ../testcases/run/run ] ||
	(cd ..; make)
ping -c 2 -t 2 $BLASTHOST > /dev/null 2>&1 ||
    { echo "Note: Can not ping \$BLASTHOST: $BLASTHOST"; }
echo "$loops" | grep -Eq "^[0-9]+$" ||
    { echo "The -l argument must be a positive number"; exit 1; }
[ -s all.exclude ] && echo "Using all.exclude"

rm -f $alllist
find `dirname $alllast` -maxdepth 1 -name $alllast -mtime +12h -delete
touch $alllast $alllog
chmod 640 $alllast $alllog
find ../testcases -perm -1 \( -name "*.debug" -o -name "*.full" \) -delete
tail -2000 $alllog > ${alllog}.new; mv ${alllog}.new $alllog
touch $allelapsed
tail -20000 $allelapsed > ${allelapsed}.new; mv ${allelapsed}.new $allelapsed

console=/dev/console
printf "\r\n" > $console &
pid=$!
sleep 1
kill -0 $pid > /dev/null 2>&1 &&
{ console=/dev/null; kill -9 $pid; }
while pgrep -q fsck; do sleep 10; done

status() {
	local s2 r

	s2=`date +%s`
	r=$(echo "elapsed $(((s2 - s1) / 86400)) day(s)," \
	    "`date -u -j -f '%s' '+%H:%M.%S' $((s2 - s1))`")
	printf "`date '+%Y%m%d %T'` all.sh done, $r\n"
	printf "`date '+%Y%m%d %T'` all.sh done, $r\r\n" > $console
}

intr() {
	printf "\nExit all.sh\n"
	./cleanup.sh
	exit 1
}
trap status EXIT
trap intr INT

[ -f all.debug.inc ] && . all.debug.inc
s1=`date +%s`
while true; do
	exclude=`sed -n '/^# Start of list/,/^# End of list/p' < $0 |
	    cat - all.exclude 2>/dev/null |
	    grep "\.sh" | awk '{print $2}'`
	list=`echo *.sh`
	[ $# -ne 0 ] && list=$*
	list=`echo $list |
	     sed  "s/[[:<:]]all\.sh[[:>:]]//g;\
	           s/[[:<:]]cleanup\.sh[[:>:]]//g"`

	if [ -n "$noshuffle" -a $# -eq 0 ]; then
		last=`cat $alllast`
		if [ -n "$last" ]; then
			last=`basename $last`
			l=`echo "$list" | sed "s/.*$last//"`
			[ -z "$l" ] && l=$list	# start over
			list=$l
			echo "Resuming test at `echo "$list" |
			    awk '{print $1}'`"
		fi
	fi
	[ -n "$noshuffle" ] ||
	    list=`echo $list | tr ' ' '\n' | sort -R |
	        tr '\n' ' '`

	lst=""
	for i in $list; do
		[ -z "$all" ] && echo $exclude | grep -qw `basename $i` &&
		    continue
		lst="$lst $i"
	done
	[ -z "$lst" ] && exit
	echo "$lst" > $alllist

	pgrep -fq vmstat.sh ||
	    daemon ../tools/vmstat.sh > /tmp/stress2.d/vmstat 2>&1

	n1=0
	n2=`echo $lst | wc -w | sed 's/ //g'`
	for i in $lst; do
		i=`basename $i`
		n1=$((n1 + 1))
		echo $i > $alllast
		./cleanup.sh || exit 1
		ts=`date '+%Y%m%d %T'`
		echo "$ts all: $i"
		printf "$ts all ($n1/$n2): $i\n" >> $alllog
		printf "$ts all ($n1/$n2): $i\r\n" > $console
		logger "Starting test all: $i"
		[ $all_debug ] && pre_debug
		[ -f $i ] || loops=1	# break
		sync; sleep .5; sync; sleep .5
		grep -E "^USE_TIMEOUT=1" $i && TIMEOUT_ONE=1 || unset TIMEOUT_ONE
		start=`date '+%s'`
		(
		 	if [ $USE_TIMEOUT ] || [ $TIMEOUT_ONE ]; then
				timeout -k 1m 1h ./$i
			else
				./$i
			fi
			e=$?
			[ $e -ne 0 ] &&
			    echo "FAIL $i exit code $e"
		) 2>&1 | tee $alloutput
		ts=`date '+%Y%m%d %T'`
		grep -qw FAIL $alloutput &&
		    echo "$ts $rev $i" >> $allfaillog &&
		    logger "stress2 test $i failed"
		grep -qw FATAL $alloutput && exit $e
		rm -f $alloutput
		printf "$ts $rev $i $((`date '+%s'` - start))\n" >> \
		    $allelapsed
		[ -f ../tools/ministat.sh ] &&
		    ../tools/ministat.sh $allelapsed $i
		[ $((`date '+%s'` - start)) -gt 1980 ] &&
		    printf "$ts *** Excessive run time: %s %d min\r\n" $i, \
		        $(((`date '+%s'` - start) / 60)) |
		    tee $console >> $allexcess
		while pgrep -q "^swap$"; do
			echo "swap still running"
			sleep 2
		done
		[ $USE_SWAPOFF ] && { swapoff -a; swapon -a; }
		[ $all_debug ] && post_debug
		[ $minutes ] && [ $((`date +%s` - s1)) -ge $minutes ] && break 2
	done
	[ $((loops -= 1)) -eq 0 ] && break
done
[ -x ../tools/fail.sh ] && ../tools/fail.sh
find /tmp . -name "*.core" -mtime -2 -maxdepth 2 -ls 2>/dev/null
