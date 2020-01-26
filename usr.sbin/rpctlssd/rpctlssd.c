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

/* Modified from gssd.c for the server side of kernel RPC-over-TLS. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <err.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rpc/rpc.h>
#include <rpc/rpc_com.h>
#include <rpc/rpcsec_tls.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "rpctlssd.h"

#ifndef _PATH_RPCTLSSDSOCK
#define _PATH_RPCTLSSDSOCK	"/var/run/rpctlssd.sock"
#define _PATH_RPCTLSSDS	"S/var/run/rpctlssd.sock"
#endif
#ifndef	_PATH_CERTANDKEY
#define	_PATH_CERTANDKEY	"/etc/rpctlssd/"
#endif

static int	rpctls_debug_level;
static int	rpctls_verbose;
static int	testnossl;
static SSL_CTX	*rpctls_ctx = NULL;
static char	*rpctls_cafiles = NULL;
static char	*rpctls_verify_loc = NULL;

static void	rpctlssd_terminate(int);
static SSL_CTX	*rpctls_setup_ssl(char *certdir);
static SSL	*rpctls_server(SSL_CTX *ctx, int s);

extern void rpctlssd_1(struct svc_req *rqstp, SVCXPRT *transp);
extern int gssd_syscall(const char *path);

int
main(int argc, char **argv)
{
	/*
	 * We provide an RPC service on a local-domain socket. The
	 * kernel rpctls code will upcall to this daemon to do the initial
	 * TLS handshake.
	 */
	struct sockaddr_un sun;
	int fd, oldmask, ch, debug;
	SVCXPRT *xprt;

	debug = 0;
	rpctls_verbose = 0;
	testnossl = 0;
	while ((ch = getopt(argc, argv, "c:dl:tv")) != -1) {
		switch (ch) {
		case 'c':
			rpctls_cafiles = optarg;
			break;
		case 'd':
			rpctls_debug_level++;
			break;
		case 'l':
			rpctls_verify_loc = optarg;
			break;
		case 't':
			testnossl = 1;
			break;
		case 'v':
			rpctls_verbose = 1;
			break;
		default:
			fprintf(stderr, "usage: %s [-c <cafile>] [-d] "
			    "[-l <verify locations>] [-v]\n", argv[0]);
			exit(1);
			break;
		}
	}
	if ((rpctls_cafiles != NULL && rpctls_verify_loc == NULL) ||
	    (rpctls_cafiles == NULL && rpctls_verify_loc != NULL)) {
		fprintf(stderr, "usage: %s [-c <cafile>] [-d] "
		    "[-l <verify locations>] [-v]\n", argv[0]);
		exit(1);
	}

	if (rpctls_debug_level == 0) {
		if (daemon(0, 0) != 0)
			err(1, "Can't daemonize");
		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
	}
	signal(SIGTERM, rpctlssd_terminate);
	signal(SIGPIPE, rpctlssd_terminate);

	memset(&sun, 0, sizeof sun);
	sun.sun_family = AF_LOCAL;
	unlink(_PATH_RPCTLSSDSOCK);
	strcpy(sun.sun_path, _PATH_RPCTLSSDSOCK);
	sun.sun_len = SUN_LEN(&sun);
	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR, "Can't create local rpctlssd socket");
			exit(1);
		}
		err(1, "Can't create local rpctlssd socket");
	}
	oldmask = umask(S_IXUSR|S_IRWXG|S_IRWXO);
	if (bind(fd, (struct sockaddr *)&sun, sun.sun_len) < 0) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR, "Can't bind local rpctlssd socket");
			exit(1);
		}
		err(1, "Can't bind local rpctlssd socket");
	}
	umask(oldmask);
	if (listen(fd, SOMAXCONN) < 0) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR,
			    "Can't listen on local rpctlssd socket");
			exit(1);
		}
		err(1, "Can't listen on local rpctlssd socket");
	}
	xprt = svc_vc_create(fd, RPC_MAXDATASIZE, RPC_MAXDATASIZE);
	if (!xprt) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR,
			    "Can't create transport for local rpctlssd socket");
			exit(1);
		}
		err(1, "Can't create transport for local rpctlssd socket");
	}
	if (!svc_reg(xprt, RPCTLSSD, RPCTLSSDVERS, rpctlssd_1, NULL)) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR,
			    "Can't register service for local rpctlssd socket");
			exit(1);
		}
		err(1, "Can't register service for local rpctlssd socket");
	}

	rpctls_ctx = rpctls_setup_ssl(_PATH_CERTANDKEY);
	if (rpctls_ctx == NULL) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR, "Can't create SSL context");
			exit(1);
		}
		err(1, "Can't create SSL context");
	}

	gssd_syscall(_PATH_RPCTLSSDS);
	svc_run();
	gssd_syscall("S");

	SSL_CTX_free(rpctls_ctx);
	EVP_cleanup();
	return (0);
}

static void
rpctlssd_verbose_out(const char *fmt, ...)
{
	va_list ap;

	if (rpctls_verbose != 0) {
		va_start(ap, fmt);
		if (rpctls_debug_level == 0)
			vsyslog(LOG_INFO | LOG_DAEMON, fmt, ap);
		else
			vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}

bool_t
rpctlssd_null_1_svc(void *argp, void *result, struct svc_req *rqstp)
{

	rpctlssd_verbose_out("rpctlssd_null_svc: done\n");
	return (TRUE);
}

bool_t
rpctlssd_connect_1_svc(void *argp, void *result, struct svc_req *rqstp)
{
	int s;
	SSL *ssl;

	rpctlssd_verbose_out("rpctlsd_connect_svc: started\n");
	/* Get the socket fd from the kernel. */
	s = gssd_syscall("E");
rpctlssd_verbose_out("rpctlsd_connect_svc s=%d\n", s);
	if (s < 0)
		return (FALSE);

	if (testnossl == 0) {
		/* Do the server side of a TLS handshake. */
		ssl = rpctls_server(rpctls_ctx, s);
		if (ssl == NULL)
			rpctlssd_verbose_out("rpctlssd_connect_svc: ssl accept "
			    "failed\n");
		else
			rpctlssd_verbose_out("rpctlssd_connect_svc: "
			    "succeeded\n");
	}

	/* Done with socket fd, so let the kernel know. */
	gssd_syscall("F");
	if (testnossl == 0 && ssl == NULL)
		return (FALSE);
	return (TRUE);
}

int
rpctlssd_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result)
{

	return (TRUE);
}

static void
rpctlssd_terminate(int sig __unused)
{

	gssd_syscall("S");
	exit(0);
}

static SSL_CTX *
rpctls_setup_ssl(char *certdir)
{
	SSL_CTX *ctx;
	char path[PATH_MAX];
	size_t len, rlen;
	int ret;

	OpenSSL_add_all_algorithms();

	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL) {
		rpctlssd_verbose_out("rpctls_setup_ssl: SSL_CTX_new failed\n");
		return (NULL);
	}
	SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Get the cert.pem and key.pem files from the directory certdir. */
	len = strlcpy(path, certdir, sizeof(path));
	rlen = sizeof(path) - len;
	if (strlcpy(&path[len], "cert.pem", rlen) != 8) {
		SSL_CTX_free(ctx);
		return (NULL);
	}
	ret = SSL_CTX_use_certificate_file(ctx, path, SSL_FILETYPE_PEM);
	if (ret != 1) {
		rpctlssd_verbose_out("rpctls_setup_ssl: can't use certificate "
		    "file path=%s ret=%d\n", path, ret);
		SSL_CTX_free(ctx);
		return (NULL);
	}
	if (strlcpy(&path[len], "key.pem", rlen) != 7) {
		SSL_CTX_free(ctx);
		return (NULL);
	}
	ret = SSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM);
	if (ret != 1) {
		rpctlssd_verbose_out("rpctls_setup_ssl: Can't use private "
		    "key path=%s ret=%d\n", path, ret);
		SSL_CTX_free(ctx);
		return (NULL);
	}

	/* Set Mutual authentication, as required. */
	if (rpctls_cafiles != NULL && rpctls_verify_loc != NULL) {
		rpctlssd_verbose_out("rpctls_setup_ssl: set mutual "
		    "authentication cafiles=%s verf_loc=%s\n", rpctls_cafiles,
		    rpctls_verify_loc);
		ret = SSL_CTX_load_verify_locations(ctx, rpctls_verify_loc,
		    NULL);
		if (ret != 1) {
			rpctlssd_verbose_out("rpctls_setup_ssl: Can't load "
			    "verify locations\n");
			SSL_CTX_free(ctx);
			return (NULL);
		}
		SSL_CTX_set_client_CA_list(ctx,
		    SSL_load_client_CA_file(rpctls_cafiles));
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |
		    SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	}
	return (ctx);
}

static SSL *
rpctls_server(SSL_CTX *ctx, int s)
{
	SSL *ssl;
	int ret;

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		rpctlssd_verbose_out("rpctls_server: SSL_new failed\n");
		return (NULL);
	}
	if (SSL_set_fd(ssl, s) != 1) {
		rpctlssd_verbose_out("rpctls_server: SSL_set_fd failed\n");
		SSL_free(ssl);
		return (NULL);
	}
	ret = SSL_accept(ssl);
	if (ret != 1) {
		rpctlssd_verbose_out("rpctls_server: SS_accept failed ret=%d\n",
		    ret);
		SSL_free(ssl);
		return (NULL);
	}
	return (ssl);
}

