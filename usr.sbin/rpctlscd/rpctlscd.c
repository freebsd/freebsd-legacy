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

/* Modified from gssd.c for the client side of kernel RPC-over-TLS. */

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

#include "rpctlscd.h"

#ifndef _PATH_RPCTLSCDSOCK
#define _PATH_RPCTLSCDSOCK	"/var/run/rpctlscd.sock"
#endif

static int	rpctls_debug_level;
static int	rpctls_verbose;
static int testnossl;
static SSL_CTX	*rpctls_ctx = NULL;

static void	rpctlscd_terminate(int);
static SSL_CTX	*rpctls_setupcl_ssl(char *certpath);
static SSL	*rpctls_connect(SSL_CTX *ctx, int s);

extern void rpctlscd_1(struct svc_req *rqstp, SVCXPRT *transp);
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
	int fd, oldmask, ch;
	SVCXPRT *xprt;
	char *certpath;

	rpctls_verbose = 0;
	testnossl = 0;
	certpath = NULL;
	while ((ch = getopt(argc, argv, "c:dtv")) != -1) {
		switch (ch) {
		case 'c':
			certpath = optarg;
		case 'd':
			rpctls_debug_level++;
			break;
		case 't':
			testnossl = 1;
			break;
		case 'v':
			rpctls_verbose = 1;
			break;
		default:
			fprintf(stderr, "usage: %s [-d] [-v]\n", argv[0]);
			exit(1);
			break;
		}
	}

	if (!rpctls_debug_level) {
		if (daemon(0, 0) != 0)
			err(1, "Can't daemonize");
		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
	}
	signal(SIGTERM, rpctlscd_terminate);
	signal(SIGPIPE, rpctlscd_terminate);

	memset(&sun, 0, sizeof sun);
	sun.sun_family = AF_LOCAL;
	unlink(_PATH_RPCTLSCDSOCK);
	strcpy(sun.sun_path, _PATH_RPCTLSCDSOCK);
	sun.sun_len = SUN_LEN(&sun);
	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR, "Can't create local rpctlscd socket");
			exit(1);
		}
		err(1, "Can't create local rpctlscd socket");
	}
	oldmask = umask(S_IXUSR|S_IRWXG|S_IRWXO);
	if (bind(fd, (struct sockaddr *)&sun, sun.sun_len) < 0) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR, "Can't bind local rpctlscd socket");
			exit(1);
		}
		err(1, "Can't bind local rpctlscd socket");
	}
	umask(oldmask);
	if (listen(fd, SOMAXCONN) < 0) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR,
			    "Can't listen on local rpctlscd socket");
			exit(1);
		}
		err(1, "Can't listen on local rpctlscd socket");
	}
	xprt = svc_vc_create(fd, RPC_MAXDATASIZE, RPC_MAXDATASIZE);
	if (!xprt) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR,
			    "Can't create transport for local rpctlscd socket");
			exit(1);
		}
		err(1, "Can't create transport for local rpctlscd socket");
	}
	if (!svc_reg(xprt, RPCTLSCD, RPCTLSCDVERS, rpctlscd_1, NULL)) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR,
			    "Can't register service for local rpctlscd socket");
			exit(1);
		}
		err(1, "Can't register service for local rpctlscd socket");
	}

	/* Set up the OpenSSL TSL stuff. */
	rpctls_ctx = rpctls_setupcl_ssl(certpath);
	if (rpctls_ctx == NULL) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR, "Can't set up TSL context");
			exit(1);
		}
		err(1, "Can't set up TSL context");
	}

	gssd_syscall(_PATH_RPCTLSCDSOCK);
	svc_run();
	gssd_syscall("");

	SSL_CTX_free(rpctls_ctx);
	EVP_cleanup();
	return (0);
}

static void
rpctlscd_verbose_out(const char *fmt, ...)
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
rpctlscd_null_1_svc(void *argp, void *result, struct svc_req *rqstp)
{

	rpctlscd_verbose_out("rpctlscd_null: done\n");
	return (TRUE);
}

bool_t
rpctlscd_connect_1_svc(void *argp, void *result, struct svc_req *rqstp)
{
	int s;
	bool_t res;
	SSL *ssl;
	char buf[1024];
	ssize_t siz, ret;

	rpctlscd_verbose_out("rpctlsd_connect: started\n");
	/* Get the socket fd from the kernel. */
	s = gssd_syscall("C");
rpctlscd_verbose_out("rpctlsd_connect s=%d\n", s);
	if (s < 0)
		return (FALSE);

	if (testnossl == 0) {
		/* Do a TLS connect handshake. */
		ssl = rpctls_connect(rpctls_ctx, s);
		if (ssl == NULL)
			rpctlscd_verbose_out("rpctlsd_connect: can't do TLS "
			    "handshake\n");
		else {
			/* Read the 478 bytes of junk off the socket. */
			siz = 478;
			ret = 1;
			while (siz > 0 && ret > 0) {
				ret = recv(s, &buf[478 - siz], siz, 0);
				siz -= ret;
			}
		}
	}

	/* Done with socket fd, so let the kernel know. */
	gssd_syscall("D");
	if (ssl == NULL)
		return (FALSE);
	return (TRUE);
}

int
rpctlscd_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result)
{

	return (TRUE);
}

static void
rpctlscd_terminate(int sig __unused)
{

	gssd_syscall("");
	exit(0);
}

static SSL_CTX *
rpctls_setupcl_ssl(char *certpath)
{
	SSL_CTX *ctx;
	long flags;
	int ret;

	OpenSSL_add_all_algorithms();

	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL) {
		rpctlscd_verbose_out("rpctls_setupcl_ssl: SSL_CTX_new "
		    "failed\n");
		return (NULL);
	}
	SSL_CTX_set_ecdh_auto(ctx, 1);

	/*
	 * If certpath is set, it refers to the certifcate file to be used
	 * during an SSL_connect().
	 */
	if (certpath != NULL) {
		ret = SSL_CTX_use_certificate_file(ctx, certpath,
		    SSL_FILETYPE_PEM);
		if (ret != 1) {
			rpctlscd_verbose_out("rpctls_setupcl_ssl: can't use "
			    "the certificate file %s\n", certpath);
			SSL_CTX_free(ctx);
			return (NULL);
		}
	}

	/* RPC-over-TLS must use TLSv1.3. */
	flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
	    SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
	SSL_CTX_set_options(ctx, flags);
	return (ctx);
}

static SSL *
rpctls_connect(SSL_CTX *ctx, int s)
{
	SSL *ssl;
	X509 *cert;
	int ret;

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		rpctlscd_verbose_out("rpctls_connect: SSL_new failed\n");
		return (NULL);
	}
	if (SSL_set_fd(ssl, s) != 1) {
		rpctlscd_verbose_out("rpctls_connect: SSL_set_fd failed\n");
		SSL_free(ssl);
		return (NULL);
	}
	ret = SSL_connect(ssl);
	if (ret != 1) {
		rpctlscd_verbose_out("rpctls_connect: SSL_connect failed %d\n",
		    ret);
		SSL_free(ssl);
		return (NULL);
	}

	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		rpctlscd_verbose_out("rpctls_connect: get peer certificate "
		    "failed\n");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		return (NULL);
	}
	X509_free(cert);

#ifdef notnow
	ret = BIO_get_ktls_send(SSL_get_wbio(ssl));
	fprintf(stderr, "ktls_send=%d\n", ret);
	ret = BIO_get_ktls_recv(SSL_get_rbio(ssl));
	fprintf(stderr, "ktls_recv=%d\n", ret);
#endif
	return (ssl);
}

