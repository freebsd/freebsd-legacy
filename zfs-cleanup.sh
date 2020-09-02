#!/bin/sh
#
# $FreeBSD$
#

usage() {
	echo "$(basename ${0}) -d -c /path/to/configuration/file"
	exit 1
}

zfs_teardown() {
	for r in ${revs}; do
		for a in ${archs}; do
			for k in ${kernels}; do
			for t in ${types}; do
				s="${r}-${a}-${k}-${t}"
				c="${r}-${a}-${t}"
				if [ -e ${scriptdir}/${s}.conf ];
				then
					zfs list ${zfs_parent}/${s}-src >/dev/null 2>&1
					rc=$?
					if [ ${rc} -eq 0 ]; then
						echo -n "${pfx} Destroying " \
							>/dev/stdout
						echo " ${zfs_parent}/${s}-src" \
							>/dev/stdout
						zfs destroy -f ${zfs_parent}/${s}-src
					fi
					zfs list ${zfs_parent}/${s}-ports >/dev/null 2>&1
					rc=$?
					if [ ${rc} -eq 0 ]; then
						echo -n "${pfx} Destroying " \
							>/dev/stdout
						echo " ${zfs_parent}/${s}-ports" \
							>/dev/stdout
						zfs destroy -f ${zfs_parent}/${s}-ports
					fi
					zfs list ${zfs_parent}/${s}-doc >/dev/null 2>&1
					rc=$?
					if [ ${rc} -eq 0 ]; then
						echo -n "${pfx} Destroying " \
							>/dev/stdout
						echo " ${zfs_parent}/${s}-doc" \
							>/dev/stdout
						zfs destroy -f ${zfs_parent}/${s}-doc
					fi
					zfs list ${zfs_parent}/${c}-chroot >/dev/null 2>&1
					rc=$?
					if [ ${rc} -eq 0 ]; then
						echo -n "${pfx} Destroying " \
							>/dev/stdout
						echo " ${zfs_parent}/${c}-chroot" \
							>/dev/stdout
						zfs destroy -f ${zfs_parent}/${c}-chroot
					fi
					zfs list ${zfs_parent}/${s} >/dev/null 2>&1
					rc=$?
					if [ ${rc} -eq 0 ]; then
						echo -n "${pfx} Destroying " \
							>/dev/stdout
						echo " ${zfs_parent}/${s}" \
							>/dev/stdout
						zfs destroy -f ${zfs_parent}/${s}
					fi
				fi
			done
			done
		done
	done

	for r in ${revs}; do
		for t in ${types}; do
			for i in src doc ports; do
				zfs list ${zfs_parent}/${r}-${i}-${t}@clone >/dev/null 2>&1
				rc=$?
				if [ ${rc} -eq 0 ]; then
					echo -n "${pfx} Destroying " \
						>/dev/stdout
					echo " ${zfs_parent}/${r}-${i}-${t}@clone" \
						>/dev/stdout
					zfs destroy -f ${zfs_parent}/${r}-${i}-${t}@clone
				fi
				zfs list ${zfs_parent}/${r}-${i}-${t} >/dev/null 2>&1
				rc=$?
				if [ ${rc} -eq 0 ]; then
					echo -n "${pfx} Destroying " \
						>/dev/stdout
					echo " ${zfs_parent}/${r}-${i}-${t}" \
						>/dev/stdout
					zfs destroy -f ${zfs_parent}/${r}-${i}-${t}
				fi
			done
		done
	done

	# XXX
	zfs destroy ${zfs_parent}/releng/scripts-${t}shot/chroots
	zfs destroy ${zfs_parent}/releng/scripts-${t}shot
	zfs destroy ${zfs_parent}/releng
	zfs destroy ${zfs_parent}/${r}-ports-${t}@clone
	zfs destroy ${zfs_parent}/${r}-src-${t}@clone
	zfs destroy ${zfs_parent}/releng/scripts-${t}shot/chroots/${r}/amd64/snap
	zfs destroy ${zfs_parent}/releng/scripts-${t}shot/chroots/${r}/amd64
	zfs destroy ${zfs_parent}/releng/scripts-${t}shot/chroots/${r}
	zfs destroy ${zfs_parent}/${r}-chroots-${t}
	zfs destroy ${zfs_parent}/${r}-logs-${t}
	zfs destroy ${zfs_parent}/${r}-ports-${t}
	zfs destroy ${zfs_parent}/${r}-src-${t}
	# XXX

	zfs destroy ${zfs_parent}/${r}-amd64-worldseed-${t}@clone
	zfs destroy ${zfs_parent}/${r}-amd64-worldseed-${t}
	zfs destroy ${zfs_parent}/${r}-i386-worldseed-${t}@clone
	zfs destroy ${zfs_parent}/${r}-i386-worldseed-${t}

	echo -n "ZFS datasets were destroyed.  They will be created"
	echo " automatically via thermite.sh."

	return 0
}

main() {
	export __BUILDCONFDIR="$(dirname $(realpath ${0}))"
	CSCONF=

	while getopts "c:d" opt; do
		case ${opt} in
			c)
				CSCONF="${OPTARG}"
				;;
			d)
				delete_only=1
				;;
			*)
				;;
		esac
	done
	shift $(( ${OPTIND} - 1 ))

	if [ -z "${CSCONF}" ]; then
		echo "Build configuration file is required."
		usage
	fi

	CSCONF="$(realpath ${CSCONF})"

	if [ ! -f "${CSCONF}" ]; then
		echo "Build configuration is not a regular file."
		exit 1
	fi

	. "${CSCONF}"

	if [ ${use_zfs} -eq 0 ]; then
		echo "== use_zfs is set to '0'; skipping." >/dev/stdout
		exit 0
	fi

	pfx="==="

	delete_only=1
	zfs_teardown
	zfs_teardown
}

main "$@"
