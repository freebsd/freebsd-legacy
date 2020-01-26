/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2008 Isilon Inc http://www.isilon.com/
 * Authors: Doug Rabson <dfr@rabson.org>
 * Developed with Red Inc: Alfred Perlstein <alfred@freebsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Modified from the kernel GSSAPI code for RPC-over-TLS. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/socketvar.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>

#include <rpc/rpc.h>
#include <rpc/rpc_com.h>
#include <rpc/rpcsec_tls.h>

#include "rpctlscd.h"
#include "rpctlssd.h"

extern struct fileops badfileops;

/*
 * Syscall hooks
 */
static struct syscall_helper_data rpctls_syscalls[] = {
	SYSCALL_INIT_HELPER(gssd_syscall),
	SYSCALL_INIT_LAST
};

#ifdef notnow
struct rpctls_syscall_args {
	char op_l_[PADL_(int)]; int op; char op_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
};
#endif

static CLIENT		*rpctls_connect_handle;
static struct mtx	rpctls_connect_lock;
static struct socket	*rpctls_connect_so = NULL;
static struct file	*rpctls_connect_fp = NULL;
static int		rpctls_connect_fd = -1;
static CLIENT		*rpctls_server_handle;
static struct mtx	rpctls_server_lock;
static struct socket	*rpctls_server_so = NULL;
static struct file	*rpctls_server_fp = NULL;
static int		rpctls_server_fd = -1;
static struct opaque_auth rpctls_null_verf;

static CLIENT		*rpctls_connect_client(void);
static CLIENT		*rpctls_server_client(void);

static void
rpctls_init(void *dummy)
{
	int error;

	error = syscall_helper_register(rpctls_syscalls, SY_THR_STATIC_KLD);
	if (error != 0)
		printf("rpctls_init: cannot register syscall\n");
	mtx_init(&rpctls_connect_lock, "rpctls_connect_lock", NULL,
	    MTX_DEF);
	mtx_init(&rpctls_server_lock, "rpctls_server_lock", NULL,
	    MTX_DEF);
	rpctls_null_verf.oa_flavor = AUTH_NULL;
	rpctls_null_verf.oa_base = RPCTLS_START_STRING;
	rpctls_null_verf.oa_length = strlen(RPCTLS_START_STRING);
printf("RPCTLS init done\n");
}
SYSINIT(rpctls_init, SI_SUB_KMEM, SI_ORDER_ANY, rpctls_init, NULL);

int
sys_gssd_syscall(struct thread *td, struct gssd_syscall_args *uap)
{
        struct sockaddr_un sun;
        struct netconfig *nconf;
	struct file *fp;
	struct socket *so;
	char path[MAXPATHLEN], *pathp;
	int fd, error, retry_count = 5;
	CLIENT *cl, *oldcl;
	bool ssd;
        
printf("in gssd syscall\n");
	error = priv_check(td, PRIV_NFS_DAEMON);
printf("aft priv_check=%d\n", error);
	if (error != 0)
		return (error);

#ifdef notyet
	switch (uap->op) {
	case RPCTLS_SYSC_SETPATH:
#else
		error = copyinstr(uap->path, path, sizeof(path), NULL);
printf("setting err=%d path=%s\n", error, path);
	if (error != 0)
		return (error);
	if (path[0] == 'S') {
		ssd = true;
		pathp = &path[1];
	} else {
		ssd = false;
		pathp = &path[0];
	}
	if (pathp[0] == '/' || pathp[0] == '\0') {
#endif
	if (ssd) {
		if (error == 0 && strlen(pathp) + 1 > sizeof(sun.sun_path))
			error = EINVAL;
	
		if (error == 0 && pathp[0] != '\0') {
			sun.sun_family = AF_LOCAL;
			strlcpy(sun.sun_path, pathp, sizeof(sun.sun_path));
			sun.sun_len = SUN_LEN(&sun);
			
			nconf = getnetconfigent("local");
			cl = clnt_reconnect_create(nconf,
			    (struct sockaddr *)&sun, RPCTLSSD, RPCTLSSDVERS,
			    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
printf("got cl=%p\n", cl);
			/*
			 * The number of retries defaults to INT_MAX, which
			 * effectively means an infinite, uninterruptable loop. 
			 * Limiting it to five retries keeps it from running
			 * forever.
			 */
			if (cl != NULL)
				CLNT_CONTROL(cl, CLSET_RETRIES, &retry_count);
		} else
			cl = NULL;
	
		mtx_lock(&rpctls_server_lock);
		oldcl = rpctls_server_handle;
		rpctls_server_handle = cl;
		mtx_unlock(&rpctls_server_lock);
	
printf("cl=%p oldcl=%p\n", cl, oldcl);
		if (oldcl != NULL) {
			CLNT_CLOSE(oldcl);
			CLNT_RELEASE(oldcl);
		}
	} else {
		if (error == 0 && strlen(pathp) + 1 > sizeof(sun.sun_path))
			error = EINVAL;
	
		if (error == 0 && pathp[0] != '\0') {
			sun.sun_family = AF_LOCAL;
			strlcpy(sun.sun_path, pathp, sizeof(sun.sun_path));
			sun.sun_len = SUN_LEN(&sun);
			
			nconf = getnetconfigent("local");
			cl = clnt_reconnect_create(nconf,
			    (struct sockaddr *)&sun, RPCTLSCD, RPCTLSCDVERS,
			    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
printf("got cl=%p\n", cl);
			/*
			 * The number of retries defaults to INT_MAX, which
			 * effectively means an infinite, uninterruptable loop. 
			 * Limiting it to five retries keeps it from running
			 * forever.
			 */
			if (cl != NULL)
				CLNT_CONTROL(cl, CLSET_RETRIES, &retry_count);
		} else
			cl = NULL;
	
		mtx_lock(&rpctls_connect_lock);
		oldcl = rpctls_connect_handle;
		rpctls_connect_handle = cl;
		mtx_unlock(&rpctls_connect_lock);
	
printf("cl=%p oldcl=%p\n", cl, oldcl);
		if (oldcl != NULL) {
			CLNT_CLOSE(oldcl);
			CLNT_RELEASE(oldcl);
		}
	}
	} else if (path[0] == 'C') {
printf("In connect\n");
		KASSERT(rpctls_connect_so != NULL,
		    ("rpctlsc syscall so != NULL"));
		KASSERT(rpctls_connect_fd == -1,
		    ("rpctlsc syscall fd not -1"));
		error = falloc(td, &fp, &fd, 0);
printf("falloc=%d fd=%d\n", error, fd);
		if (error == 0) {
			mtx_lock(&rpctls_connect_lock);
			so = rpctls_connect_so;
			rpctls_connect_so = NULL;
			rpctls_connect_fp = fp;
			rpctls_connect_fd = fd;
			mtx_unlock(&rpctls_connect_lock);
			finit(fp, FREAD | FWRITE, DTYPE_SOCKET, so, &socketops);
			td->td_retval[0] = fd;
		}
printf("returning=%d\n", fd);
	} else if (path[0] == 'D') {
printf("In EOconnect\n");
		mtx_lock(&rpctls_connect_lock);
		fd = rpctls_connect_fd;
		rpctls_connect_fd = -1;
		fp = rpctls_connect_fp;
		rpctls_connect_fp = NULL;
		mtx_unlock(&rpctls_connect_lock);
printf("fd=%d\n", fd);
		if (fd >= 0) {
			/*
			 * Since the daemon will not be using the fd any
			 * more, we want to close the fd, but we do not
			 * want to soclose() the associated socket.
			 * Set f_ops == badfileops so that kern_close() will
			 * not do a soclose().
			 */
			fp->f_ops = &badfileops;
			kern_close(td, fd);
printf("aft kern_close\n");
		} else
			printf("rpctlsc fd -1\n");
	} else if (path[0] == 'E') {
printf("In srvconnect\n");
		KASSERT(rpctls_server_so != NULL,
		    ("rpctlss syscall so != NULL"));
		KASSERT(rpctls_server_fd == -1,
		    ("rpctlss syscall fd not -1"));
		error = falloc(td, &fp, &fd, 0);
printf("srv falloc=%d fd=%d\n", error, fd);
		if (error == 0) {
			mtx_lock(&rpctls_server_lock);
			so = rpctls_server_so;
			rpctls_server_so = NULL;
			rpctls_server_fp = fp;
			rpctls_server_fd = fd;
			mtx_unlock(&rpctls_server_lock);
			finit(fp, FREAD | FWRITE, DTYPE_SOCKET, so, &socketops);
			td->td_retval[0] = fd;
		}
printf("srv returning=%d\n", fd);
	} else if (path[0] == 'F') {
printf("In EOserver\n");
		mtx_lock(&rpctls_server_lock);
		fd = rpctls_server_fd;
		rpctls_server_fd = -1;
		fp = rpctls_server_fp;
		rpctls_server_fp = NULL;
		mtx_unlock(&rpctls_server_lock);
printf("srv fd=%d\n", fd);
		if (fd >= 0) {
			/*
			 * Since the daemon will not be using the fd any
			 * more, we want to close the fd, but we do not
			 * want to soclose() the associated socket.
			 * Set f_ops == badfileops so that kern_close() will
			 * not do a soclose().
			 */
			fp->f_ops = &badfileops;
			kern_close(td, fd);
printf("srv aft kern_close\n");
		} else
			printf("rpctlss fd -1\n");
	}

	return (error);
}

/*
 * Acquire the rpctls_connect_handle and return it with a reference count,
 * if it is available.
 */
static CLIENT *
rpctls_connect_client(void)
{
	CLIENT *cl;

	mtx_lock(&rpctls_connect_lock);
	cl = rpctls_connect_handle;
	if (cl != NULL)
		CLNT_ACQUIRE(cl);
	mtx_unlock(&rpctls_connect_lock);
	return (cl);
}

/*
 * Acquire the rpctls_server_handle and return it with a reference count,
 * if it is available.
 */
static CLIENT *
rpctls_server_client(void)
{
	CLIENT *cl;

	mtx_lock(&rpctls_server_lock);
	cl = rpctls_server_handle;
	if (cl != NULL)
		CLNT_ACQUIRE(cl);
	mtx_unlock(&rpctls_server_lock);
	return (cl);
}

/* Do an upcall for a new socket connect using TLS. */
enum clnt_stat
rpctls_connect(CLIENT *newclient, struct socket *so)
{
	struct rpc_callextra ext;
	struct timeval utimeout;
	enum clnt_stat stat;
	CLIENT *cl;
	int val;
	static bool rpctls_connect_busy = false;

printf("In rpctls_connect\n");
	cl = rpctls_connect_client();
printf("connect_client=%p\n", cl);
	if (cl == NULL)
		return (RPC_TLSCONNECT);

	/* First, do the AUTH_TLS NULL RPC. */
	memset(&ext, 0, sizeof(ext));
	utimeout.tv_sec = 30;
	utimeout.tv_usec = 0;
	ext.rc_auth = authtls_create();
printf("authtls=%p\n", ext.rc_auth);
	stat = clnt_call_private(newclient, &ext, NULLPROC, (xdrproc_t)xdr_void,
	    NULL, (xdrproc_t)xdr_void, NULL, utimeout);
printf("aft NULLRPC=%d\n", stat);
	AUTH_DESTROY(ext.rc_auth);
	if (stat != RPC_SUCCESS)
		return (RPC_SYSTEMERROR);

	/* Serialize the connect upcalls. */
	mtx_lock(&rpctls_connect_lock);
	while (rpctls_connect_busy)
		msleep(&rpctls_connect_busy, &rpctls_connect_lock, PVFS,
		    "rtlscn", 0);
	rpctls_connect_busy = true;
	rpctls_connect_so = so;
	mtx_unlock(&rpctls_connect_lock);
printf("rpctls_conect so=%p\n", so);

	/* Temporarily block reception during the handshake upcall. */
	val = 1;
	CLNT_CONTROL(newclient, CLSET_BLOCKRCV, &val);

	/* Do the connect handshake upcall. */
	stat = rpctlscd_connect_1(NULL, NULL, cl);
printf("aft connect upcall=%d\n", stat);
	CLNT_RELEASE(cl);

	/* Unblock reception. */
	val = 0;
	CLNT_CONTROL(newclient, CLSET_BLOCKRCV, &val);

	/* Once the upcall is done, the daemon is done with the fp and so. */
	mtx_lock(&rpctls_connect_lock);
	rpctls_connect_so = NULL;
	rpctls_connect_fd = -1;
	rpctls_connect_busy = false;
	wakeup(&rpctls_connect_busy);
	mtx_unlock(&rpctls_connect_lock);
printf("aft wakeup\n");

	return (stat);
}

/* Do an upcall for a new server socket using TLS. */
enum clnt_stat
rpctls_server(struct socket *so)
{
	enum clnt_stat stat;
	CLIENT *cl;
	static bool rpctls_server_busy = false;

printf("In rpctls_server\n");
	cl = rpctls_server_client();
printf("server_client=%p\n", cl);
	if (cl == NULL)
		return (RPC_SYSTEMERROR);

	/* Serialize the server upcalls. */
	mtx_lock(&rpctls_server_lock);
	while (rpctls_server_busy)
		msleep(&rpctls_server_busy, &rpctls_server_lock, PVFS,
		    "rtlssn", 0);
	rpctls_server_busy = true;
	rpctls_server_so = so;
	mtx_unlock(&rpctls_server_lock);
printf("rpctls_conect so=%p\n", so);

	/* Do the server upcall. */
	stat = rpctlssd_connect_1(NULL, NULL, cl);
printf("aft server upcall=%d\n", stat);
	CLNT_RELEASE(cl);

	/* Once the upcall is done, the daemon is done with the fp and so. */
	mtx_lock(&rpctls_server_lock);
	rpctls_server_so = NULL;
	rpctls_server_fd = -1;
	rpctls_server_busy = false;
	wakeup(&rpctls_server_busy);
	mtx_unlock(&rpctls_server_lock);
printf("aft wakeup\n");

	return (stat);
}

/*
 * Handle the NULL RPC with authentication flavor of AUTH_TLS.
 * This is a STARTTLS command, so do the upcall to the rpctlssd daemon,
 * which will do the TLS handshake.
 */
enum auth_stat
_svcauth_rpcsec_tls(struct svc_req *rqst, struct rpc_msg *msg)

{
	bool_t call_stat;
	enum clnt_stat stat;
	SVCXPRT *xprt;
	
	/* Initialize reply. */
	rqst->rq_verf = rpctls_null_verf;
printf("authtls: clen=%d vlen=%d fl=%d\n", rqst->rq_cred.oa_length, msg->rm_call.cb_verf.oa_length, msg->rm_call.cb_verf.oa_flavor);

	/* Check client credentials. */
	if (rqst->rq_cred.oa_length != 0 ||
	    msg->rm_call.cb_verf.oa_length != 0 ||
	    msg->rm_call.cb_verf.oa_flavor != AUTH_NULL)
		return (AUTH_BADCRED);
	
printf("authtls proc=%d\n", rqst->rq_proc);
	if (rqst->rq_proc != NULLPROC)
		return (AUTH_REJECTEDCRED);

	/*
	 * Disable reception for the krpc so that the TLS handshake can
	 * be done on the socket in the rpctlssd daemon.
	 */
	xprt = rqst->rq_xprt;
	sx_xlock(&xprt->xp_lock);
	xprt->xp_dontrcv = TRUE;
	sx_xunlock(&xprt->xp_lock);

	/*
	 * Send the reply to the NULL RPC with AUTH_TLS, which is the
	 * STARTTLS command for Sun RPC.
	 */
	call_stat = svc_sendreply(rqst, (xdrproc_t)xdr_void, NULL);
printf("authtls: null reply=%d\n", call_stat);
	if (!call_stat) {
		sx_xlock(&xprt->xp_lock);
		xprt->xp_dontrcv = FALSE;
		sx_xunlock(&xprt->xp_lock);
		xprt_active(xprt);	/* Harmless if already active. */
		return (AUTH_FAILED);
	}

	/* Do an upcall to do the TLS handshake. */
	stat = rpctls_server(rqst->rq_xprt->xp_socket);

	/* Re-enable reception on the socket within the krpc. */
	sx_xlock(&xprt->xp_lock);
	xprt->xp_dontrcv = FALSE;
	sx_xunlock(&xprt->xp_lock);
	xprt_active(xprt);		/* Harmless if already active. */
printf("authtls: aft handshake stat=%d\n", stat);

	if (stat != RPC_SUCCESS)
		return (AUTH_FAILED);
	return (RPCSEC_GSS_NODISPATCH);
}

