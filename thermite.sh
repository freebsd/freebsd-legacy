#!/bin/sh
#-
# Copyright (c) 2012, 2013 Glen Barber
# Copyright (c) 2013-2019 The FreeBSD Foundation
# Copyright (c) 2020 Rubicon Communications, LLC (netgate.com)
# All rights reserved.
#
# Portions of this software were developed by Glen Barber
# under sponsorship from the FreeBSD Foundation.
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
# Thermite is a pyrotechnic composition of shell script and zfs.
# When executed, it generates a significant amount of heat.
# Wrapper script for release.sh to automate mass release builds.
#
# $FreeBSD$
#

usage() {
	echo "$(basename ${0}) -c /path/to/configuration/file"
	exit 1
}

info() {
	out="${@}"
	printf "$(date +%Y%m%d-%H:%M:%S)\tINFO:\t${out}\n" >/dev/stdout
	unset out
}

verbose() {
	if [ -z ${debug} ] || [ ${debug} -eq 0 ]; then
		return 0
	fi
	out="${@}"
	printf "$(date +%Y%m%d-%H:%M:%S)\tDEBUG:\t${out}\n" >/dev/stdout
	unset out
}

runcmd() {
	verbose "${rev} ${arch} ${kernel} ${type}"
	eval "$@"
}

loop_revs() {
	verbose "loop_revs() start"
	for rev in ${revs}; do
		verbose "loop_revs() arguments: $@"
		eval runcmd "$@"
	done
	unset rev
	verbose "loop_revs() stop"
}

loop_archs() {
	verbose "loop_archs() start"
	for arch in ${archs}; do
		verbose "loop_archs() arguments: $@"
		eval runcmd "$@"
	done
	unset arch
	verbose "loop_archs() stop"
}

loop_kernels() {
	verbose "loop_kernels() start"
	for kernel in ${kernels}; do
		verbose "loop_kernels() arguments: $@"
		eval runcmd "$@"
	done
	unset kernel
	verbose "loop_kernel() stop"
}

loop_types() {
	verbose "loop_types() start"
	for type in ${types}; do
		verbose "loop_types() arguments: $@"
		eval runcmd "$@"
	done
	unset type
	verbose "loop_types() stop"
}

runall() {
	verbose "runall() start"
	verbose "runall() arguments: $@"
	eval loop_revs loop_archs loop_kernels loop_types "$@"
	verbose "runall() stop"
}

check_use_zfs() {
	if [ ! -c /dev/zfs ]; then
		echo "ZFS is required."
		exit 1
	fi
	return 0
}

truncate_logs() {
	source_config || return 0
	echo > ${logdir}/${rev}-${arch}-${kernel}-${type}.log
	return 0
}

source_config() {
	local configfile
	configfile="${scriptdir}/${rev}-${arch}-${kernel}-${type}.conf"
	if [ ! -e "${configfile}" ]; then
		return 1
	fi
	. "${configfile}"
	return 0
}

zfs_mount_tree() {
	source_config || return 0
	_tree=${1}
	[ -z ${_tree} ] && return 0
	seed_src=
	case ${_tree} in
		src)
			seed_src=1
			;;
		doc)
			[ ! -z ${NODOC} ] && return 0
			;;
		ports)
			[ ! -z ${NOPORTS} ] && return 0
			;;
		*)
			info "Unknown source tree type: ${_tree}"
			return 0
			;;
	esac
	_clone="${zfs_parent}/${rev}-${_tree}-${type}"
	_mount="/${zfs_mount}/${rev}-${arch}-${kernel}-${type}"
	_target="${zfs_parent}/${rev}-${arch}-${kernel}-${type}-${_tree}"
	info "Cloning ${_clone}@clone to ${_target}"
	zfs clone -p -o atime=off -o mountpoint=${_mount}/usr/${_tree} \
		${_clone}@clone ${_target}
	unset _clone _mount _target _tree _seedmount _seedtarget
}

zfs_mount_src() {
	source_config || return 0
	_tree=src
	_clone="${zfs_parent}/${rev}-${_tree}-${type}"
	# Only create chroot seeds for x86.
	case ${arch} in
		amd64|i386)
			;;
		*)
			return 0
			;;
	esac
	_seedmount=${chroots}/${rev}/${arch}/${type}
	_seedtarget="${zfs_parent}/${rev}-${arch}-${type}-chroot"
	info "Creating ${_seedtarget} from ${_clone}"
	zfs snapshot ${_clone}@clone
	zfs clone -p -o atime=off -o mountpoint=${_seedmount} \
		${_clone}@clone ${_seedtarget}
	unset _clone _mount _target _tree _seedmount _seedtarget
}

zfs_create_tree() {
	source_config || return 0
	_tree=${1}
	[ -z ${_tree} ] && return 0
	[ ! -z $(eval echo \${zfs_${_tree}_seed_${rev}_${type}}) ] && return 0
	case ${_tree} in
		src)
			return 0
			;;
		doc)
			[ ! -z ${NODOC} ] && return 0
			_gitsrc="${GITROOT}/${GITDOC}"
			;;
		ports)
			[ ! -z ${NOPORTS} ] && return 0
			_gitsrc="${GITROOT}/${GITPORTS}"
			;;
		*)
			info "Unknown source tree type: ${_tree}"
			return 0
			;;
	esac
	TREE="$(echo ${_tree} | tr '[:lower:]' '[:upper:]')"
	_clone="${zfs_parent}/${rev}-${_tree}-${type}"
	_mount="/${zfs_mount}/${rev}-${_tree}-${type}"
	info "Creating ${_clone}"
	zfs create -o atime=off -o mountpoint=${_mount} ${_clone}
	info "Source checkout ${_gitsrc} to ${_mount}"
	git clone -q -b ${TREEBRANCH} ${_gitsrc} ${_mount}
	info "Creating ZFS snapshot ${_clone}@clone"
	zfs snapshot ${_clone}@clone
	eval zfs_${_tree}_seed_${rev}_${type}=1
	unset _clone _mount _tree _gitsrc
}

zfs_bootstrap() {
	[ -z ${use_zfs} ] && return 0
	runall zfs_create_tree src
	runall zfs_create_tree ports
	runall zfs_create_tree doc
	zfs_bootstrap_done=1
}

zfs_finish_bootstrap() {
	runall zfs_mount_tree src
	runall zfs_mount_tree ports
	runall zfs_mount_tree doc
}

prebuild_setup() {
	[ ! -z $(eval echo \${zfs_${_tree}_prebuild_${rev}_${type}}) ] && return 0
	_mount="${logdir}"
	_clone="${zfs_parent}/${rev}-logs-${type}"
	mkdir -p ${_mount}
	info "Creating ${_mount}"
	zfs create -o atime=off -o mountpoint=${_mount} ${_clone}

	_mount="${chroots}"
	_clone="${zfs_parent}/${rev}-chroots-${type}"
	mkdir -p ${_mount}
	info "Creating ${_mount}"
	zfs create -o atime=off -o mountpoint=${_mount} ${_clone}

	_mount="${srcdir}"
	_clone="${zfs_parent}/${rev}-src-${type}"
	mkdir -p ${_mount}
	info "Creating ${_mount}"
	zfs create -o atime=off -o mountpoint=${_mount} ${_clone}

	eval zfs_${_chrootarch}_prebuild_${rev}_${type}=1

	info "Checking out tree to ${srcdir}"
	git clone -q -b ${releasesrc} ${GITROOT}/${GITSRC} ${srcdir}

}

# Email log output when a stage has completed
send_logmail() {
	[ -z "${emailgoesto}" ] && return 0
	[ -z "${emailsentfrom}" ] && return 0
	local _body
	local _subject
	_subject="${2}"
	_body="$(tail -n 50 ${1})"

	printf "From: ${emailsentfrom}\nTo: ${emailgoesto}\nSubject: ${_subject}\n\n${_body}\n\n" \
		| /usr/sbin/sendmail -oi -f ${emailsentfrom} ${emailgoesto}
	return 0
}

# Email completed output
send_completed_email() {
	[ -z "${emailgoesto}" ] && return 0
	[ -z "${emailsentfrom}" ] && return 0
	local _body
	local _subject
	_subject="$(hostname -s) snapshot builds completed"
	_body="$(uname -r)"

	printf "From: ${emailsentfrom}\nTo: ${emailgoesto}\nSubject: ${_subject}\n\n${_body}\n\n" \
		| /usr/sbin/sendmail -oi -f ${emailsentfrom} ${emailgoesto}
	return 0
}

# Stage builds for ftp propagation.
ftp_stage() {
	_build="${rev}-${arch}-${kernel}-${type}"
	_conf="${scriptdir}/${_build}.conf"
	source_config || return 0
	[ -z "${EVERYTHINGISFINE}" ] && return 0

	load_stage_env
	info "Staging for ftp: ${_build}"
	[ ! -z "${EMBEDDEDBUILD}" ] && export EMBEDDEDBUILD
	[ ! -z "${BOARDNAME}" ] && export BOARDNAME
	chroot ${CHROOTDIR} make -C /usr/src/release \
		-f Makefile.mirrors \
		TARGET=${TARGET} TARGET_ARCH=${TARGET_ARCH} \
		KERNCONF=${KERNEL} WITH_VMIMAGES=${WITH_VMIMAGES} \
		WITH_DVD=${WITH_DVD} \
		ftp-stage >> ${logdir}/${_build}.log 2>&1

	if [ -z "${ftpdir}" ]; then
		info "FTP directory (ftpdir) not set."
		info "Refusing to rsync(1) to the stage area."
		return 0
	fi

	case ${type} in
		release)
			_type="releases"
			;;
		*)
			_type="snapshots"
			;;
	esac

	mkdir -p "${ftpdir}/${_type}"
	rsync -avH ${CHROOTDIR}/R/ftp-stage/${_type}/* \
		${ftpdir}/${_type}/ >> ${logdir}/${_build}.log 2>&1
	unset BOARDNAME EMBEDDEDBUILD WITH_VMIMAGES
	return 0
}

# Run the release builds.
build_release() {
	_build="${rev}-${arch}-${kernel}-${type}"
	_conf="${scriptdir}/${_build}.conf"
	source_config || return 0
	info "Building release: ${_build}"
	set >> ${logdir}/${_build}.log
	env -i __BUILDCONFDIR="${__BUILDCONFDIR}" \
		/bin/sh ${srcdir}/release/release.sh -c ${_conf} \
		>> ${logdir}/${_build}.log 2>&1

	ftp_stage
	ls -1 ${CHROOTDIR}/R/* >> ${logdir}/${_build}.log
	send_logmail ${logdir}/${_build}.log ${_build}
	unset _build _conf
}

# Run the release builds in parallel.  CAUSES INSANE CPU LOAD.
parallelbuild_release() {
	_build="${rev}-${arch}-${kernel}-${type}"
	_conf="${scriptdir}/${_build}.conf"
	source_config || return 0
	(
	info "Building release: ${_build}"
	set >> ${logdir}/${_build}.log
	env -i __BUILDCONFDIR="${__BUILDCONFDIR}" \
		/bin/sh ${srcdir}/release/release.sh -c ${_conf} \
		>> ${logdir}/${_build}.log 2>&1

	ftp_stage
	ls -1 ${CHROOTDIR}/R/* >> ${logdir}/${_build}.log
	send_logmail ${logdir}/${_build}.log ${_build}
	) &
	unset _build _conf
}

# Upload AWS EC2 AMI images.
upload_ec2_ami() {
	_build="${rev}-${arch}-${kernel}-${type}"
	_conf="${scriptdir}/${_build}.conf"
	source_config || return 0
	case ${arch}:${kernel} in
		amd64:GENERIC)
			_EC2TARGET=amd64
			_EC2TARGET_ARCH=amd64
			;;
		aarch64:GENERIC)
			# stable/11 arm64/aarch64 is not supported
			case ${rev} in
				11)
					return 0
					;;
				*)
					_EC2TARGET=arm64
					_EC2TARGET_ARCH=aarch64
					;;
			esac
			;;
		*)
			return 0
			;;
	esac
	info "Uploading EC2 AMI image for build: ${_build}"
	if [ ! -e "${CHROOTDIR}/${AWSKEYFILE}" ]; then
		cp -p ${AWSKEYFILE} ${CHROOTDIR}/${AWSKEYFILE}
		if [ $? -ne 0 ]; then
			info "Amazon EC2 key file not found."
			return 0
		fi
	fi
	if [ -z "${AWSREGION}" -o -z "${AWSBUCKET}" -o -z "${AWSKEYFILE}" ]; then
		return 0
	fi
	mount -t devfs devfs ${CHROOTDIR}/dev
	chroot ${CHROOTDIR} make -C /usr/src/release \
		AWSREGION=${AWSREGION} \
		AWSBUCKET=${AWSBUCKET} \
		AWSKEYFILE=${AWSKEYFILE} \
		EC2PUBLIC=${EC2PUBLIC} \
		EC2PUBLICSNAP=${EC2PUBLICSNAP} \
		EC2SNSTOPIC=${EC2SNSTOPIC} \
		TARGET=${_EC2TARGET} \
		TARGET_ARCH=${_EC2TARGET_ARCH} \
		ec2ami \
		>> ${logdir}/${_build}.ec2.log 2>&1
	unset _build _conf AWSREGION AWSBUCKET AWSKEYFILE EC2PUBLIC EC2SNSTOPIC EC2PUBLICSNAP
	unset _EC2TARGET _EC2TARGET_ARCH
	umount ${CHROOTDIR}/dev
	return 0
} # upload_ec2_ami()

# Upload Vagrant virtual machine images.
upload_vagrant_image() {
	_build="${rev}-${arch}-${kernel}-${type}"
	_conf="${scriptdir}/${_build}.conf"
	source_config || return 0
	case ${arch} in
		amd64)
			;;
		*)
			return 0
			;;
	esac
	if [ -z "${VAGRANT_UPLOAD_CONF}" ]; then
		return 0
	fi
	info "Uploading Vagrant virtual machine image for build: ${_build}"
	if [ ! -e "${CHROOTDIR}/${VAGRANT_UPLOAD_CONF}" ]; then
		cp -p ${VAGRANT_UPLOAD_CONF} \
			${CHROOTDIR}/${VAGRANT_UPLOAD_CONF}
		if [ $? -ne 0 ]; then
			info "Vagrant key file not found."
			return 0
		fi
	fi
	mount -t devfs devfs ${CHROOTDIR}/dev
	chroot ${CHROOTDIR} make -C /usr/src/release \
		VAGRANT_UPLOAD_CONF=${VAGRANT_UPLOAD_CONF} \
		vagrant-upload \
		>> ${logdir}/${_build}.vagrant.log 2>&1
	unset _build _conf VAGRANT_UPLOAD_CONF
	umount ${CHROOTDIR}/dev
	return 0
} # upload_vagrant_image()

# Upload Google Compute Engine virtual machine images.
upload_gce_image() {
	_build="${rev}-${arch}-${kernel}-${type}"
	_conf="${scriptdir}/${_build}.conf"
	source_config || return 0
	case ${arch} in
		amd64)
			;;
		*)
			return 0
			;;
	esac
	if [ -z "${GCE_LOGIN_SKIP}" -o -z "${GCE_BUCKET}" ]; then
		return 0
	fi
	info "Uploading GCE virtual machine image for build: ${_build}"
	if [ ! -d "${CHROOTDIR}/${GCE_CONFIG_DIR}" ]; then
		if [ ! -e "${GCE_CONFIG_PKG}" ]; then
			echo "Cannot locate config tarball."
			return 0
		fi
		mkdir -p ${CHROOTDIR}/${GCE_CONFIG_LOC}
		tar -xzf ${GCE_CONFIG_PKG} -C ${CHROOTDIR}/${GCE_CONFIG_LOC}
	fi
	mount -t devfs devfs ${CHROOTDIR}/dev
	chroot ${CHROOTDIR} make -C /usr/src/release \
		GCE_BUCKET=${GCE_BUCKET} \
		GCE_LOGIN_SKIP=1 \
		GCE_LICENSE="${GCE_LICENSE}" \
		gce-upload \
		>> ${logdir}/${_build}.gce 2>&1
	unset _build _conf GCE_BUCKET GCE_CONFIG_DIR GCE_CONFIG_PKG
	unset GCE_CONFIG_LOC GCE_LOGIN_SKIP
	umount ${CHROOTDIR}/dev
	return 0
} # upload_gce_image()

# Install amd64/i386 "seed" chroots for all branches being built.
install_chroots() {
	source_config || return 0
	case ${arch} in
		i386)
			_chrootarch="i386"
			;;
		*)
			_chrootarch="amd64"
			;;
	esac
	[ ! -z $(eval echo \${zfs_${_chrootarch}_seed_${rev}_${type}}) ] \
		&& return 0
	_clone="${zfs_parent}/${rev}-${_chrootarch}-worldseed-${type}"
	_mount="/${zfs_mount}/${rev}-${arch}-worldseed-${type}"
	_build="${rev}-${arch}-${kernel}-${type}"
	_dest="${__WRKDIR_PREFIX}/${_build}"
	_srcdir="${chroots}/${rev}/${_chrootarch}/${type}"
	_objdir="${chroots}/${rev}-obj/${_chrootarch}/${type}"
	info "Creating ${_mount}"
	zfs create -o atime=off -o mountpoint=${_mount} ${_clone}
	info "Installing ${_mount}"
	env MAKEOBJDIRPREFIX=${_objdir} \
		make -C ${_srcdir} \
		__MAKE_CONF=/dev/null SRCCONF=/dev/null \
		TARGET=${_chrootarch} TARGET_ARCH=${_chrootarch} \
		DESTDIR=${_mount} \
		installworld distribution >> \
		${logdir}/${_build}.log 2>&1

	## XXX: Temporary hack to install git from pkg(8) instead of
	##      building from ports.
	mount -t devfs devfs ${_mount}/dev
	cp /etc/resolv.conf ${_mount}/etc/resolv.conf
	env ASSUME_ALWAYS_YES=yes pkg -c ${_mount} install -y devel/git
	env ASSUME_ALWAYS_YES=yes pkg -c ${_mount} clean -y
	#mkdir -p ${_mount}/usr/ports
	#mount -t nullfs /releng/13-ports-snap ${_mount}
	#GITUNSETOPTS="CONTRIB CURL CVS GITWEB GUI HTMLDOCS"
	#GITUNSETOPTS="${GITUNSETOPTS} ICONV NLS P4 PERL"
	#GITUNSETOPTS="${GITUNSETOPTS} SEND_EMAIL SUBTREE SVN"
	#GITUNSETOPTS="${GITUNSETOPTS} PCRE PCRE2"
	#eval chroot ${_mount} env OPTIONS_UNSET=\"${GITUNSETOPTS}\" \
	#make -C /usr/ports/devel/git FORCE_PKG_REGISTER=1 \
	#	WRKDIRPREFIX=/tmp/ports \
	#	DISTDIR=/tmp/distfiles \
	#	install clean distclean
	#rm -f ${_mount}/etc/resolv.conf
	#umount ${_mount}/usr/ports
	umount ${_mount}/dev
	# End XXX

	zfs snapshot ${_clone}@clone
	eval zfs_${_chrootarch}_seed_${rev}_${type}=1
	unset _build _dest _objdir _srcdir _clone _mount

	return 0
}

zfs_clone_chroots() {
	source_config || return 0
	case ${arch} in
		i386)
			_chrootarch="i386"
			;;
		*)
			_chrootarch="amd64"
			;;
	esac
	_clone="${zfs_parent}/${rev}-${_chrootarch}-worldseed-${type}"
	_mount="/${zfs_mount}/${rev}-${arch}-worldseed-${type}"
	_build="${rev}-${arch}-${kernel}-${type}"
	_dest="${__WRKDIR_PREFIX}/${_build}"
	info "Cloning ${_chrootarch} world to ${zfs_parent}/${_build}"
	zfs clone -p -o atime=off -o mountpoint=${_dest} \
		${_clone}@clone ${zfs_parent}/${_build}
	unset _clone _mount _build _dest

	return 0
}

# Build amd64/i386 "seed" chroots for all branches being built.
build_chroots() {
	source_config || return 0
	case ${arch} in
		i386)
			_chrootarch="i386"
			;;
		*)
			_chrootarch="amd64"
			;;
	esac
	[ ! -z $(eval echo \${chroot_${_chrootarch}_build_${rev}_${type}}) ] && return 0
	_build="${rev}-${_chrootarch}-${type}"
	_srcdir="${chroots}/${rev}/${_chrootarch}/${type}"
	_objdir="${chroots}/${rev}-obj/${_chrootarch}/${type}"
	mkdir -p "${_srcdir}"
	mkdir -p "${_objdir}"
	zfs clone -p -o atime=off -o mountpoint=$(realpath ${_srcdir}) \
		${zfs_parent}/${rev}-src-${type}@clone \
		${zfs_parent}$(realpath ${_srcdir}) || exit 1
	info "Building $(realpath ${_srcdir}) world"
	env MAKEOBJDIRPREFIX=${_objdir} \
		make -C ${_srcdir} ${WORLD_FLAGS} \
		__MAKE_CONF=/dev/null SRCCONF=/dev/null \
		TARGET=${_chrootarch} TARGET_ARCH=${_chrootarch} \
		buildworld >> \
		${logdir}/${_build}.log 2>&1
	eval chroot_${_chrootarch}_build_${rev}_${type}=1
	unset _build _dest _objdir _srcdir

	return 0
}

main() {
	releasesrc="main"
	export __BUILDCONFDIR="$(dirname $(realpath ${0}))"

	while getopts "c:d" opt; do
		case ${opt} in
			c)
				CONF=${OPTARG}
				[ -e ${CONF} ] && . $(realpath ${CONF})
				;;
			d)
				debug=1
				;;
			\?)
				usage
				;;
		esac
	done
	shift $(($OPTIND - 1))
	[ -z ${CONF} ] && usage
	use_zfs=1
	check_use_zfs
	zfs_bootstrap_done=
	runall prebuild_setup
	runall truncate_logs
	zfs_bootstrap
	runall zfs_mount_src
	runall build_chroots
	runall install_chroots
	runall zfs_clone_chroots
	zfs_finish_bootstrap
	runall ${parallel}build_release
	wait
	runall upload_ec2_ami
	runall upload_gce_image
	runall upload_vagrant_image
	send_completed_email
}

main "$@"

