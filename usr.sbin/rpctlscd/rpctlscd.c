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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <err.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <rpc/rpc.h>
#include <rpc/rpc_com.h>
#include <rpc/rpcsec_tls.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "rpctlscd.h"

#ifndef _PATH_RPCTLSCDSOCK
#define _PATH_RPCTLSCDSOCK	"/var/run/rpctlscd.sock"
#endif
#ifndef	_PATH_CERTANDKEY
#define	_PATH_CERTANDKEY	"/etc/rpctlscd/"
#endif

static int		rpctls_debug_level;
static bool		rpctls_verbose;
static int testnossl;
static SSL_CTX		*rpctls_ctx = NULL;
static const char	*rpctls_verify_cafile = NULL;
static const char	*rpctls_certdir = _PATH_CERTANDKEY;
static bool		rpctls_verify = false;
static bool		rpctls_comparehost = false;

static void		rpctlscd_terminate(int);
static SSL_CTX		*rpctls_setupcl_ssl(bool cert);
static SSL		*rpctls_connect(SSL_CTX *ctx, int s);
static int		rpctls_checkhost(int s, X509 *cert);

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
	bool cert;

	rpctls_verbose = false;
	testnossl = 0;
	cert = false;
	while ((ch = getopt(argc, argv, "cD:dhl:tVv")) != -1) {
		switch (ch) {
		case 'c':
			cert = true;
			break;
		case 'D':
			rpctls_certdir = optarg;
			break;
		case 'd':
			rpctls_debug_level++;
			break;
		case 'h':
			rpctls_comparehost = true;
			break;
		case 'l':
			rpctls_verify_cafile = optarg;
			break;
		case 't':
			testnossl = 1;
			break;
		case 'V':
			rpctls_verify = true;
			break;
		case 'v':
			rpctls_verbose = true;
			break;
		default:
			fprintf(stderr, "usage: %s [-c] "
			    "[-D certdir] [-d] [-h] "
			    "[-l verify_locations_file] "
			    "[-V] [-v]\n", argv[0]);
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
	rpctls_ctx = rpctls_setupcl_ssl(cert);
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

	if (rpctls_verbose) {
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

	/* Do a TLS connect handshake. */
	ssl = rpctls_connect(rpctls_ctx, s);
	if (ssl == NULL)
		rpctlscd_verbose_out("rpctlsd_connect: can't do TLS "
		    "handshake\n");
	if (testnossl != 0 && ssl != NULL) {
		/* Read the 478 bytes of junk off the socket. */
		siz = 478;
		ret = 1;
		while (siz > 0 && ret > 0) {
			ret = recv(s, &buf[478 - siz], siz, 0);
			siz -= ret;
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
rpctls_setupcl_ssl(bool cert)
{
	SSL_CTX *ctx;
	long flags;
	char path[PATH_MAX];
	size_t len, rlen;
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
	 * If cert is true, a certificate and key exists in
	 * rpctls_certdir, so that it can do mutual authentication.
	 */
	if (cert) {
		/* Get the cert.pem and key.pem files. */
		len = strlcpy(path, rpctls_certdir, sizeof(path));
		rlen = sizeof(path) - len;
		if (strlcpy(&path[len], "cert.pem", rlen) != 8) {
			SSL_CTX_free(ctx);
			return (NULL);
		}
		ret = SSL_CTX_use_certificate_file(ctx, path,
		    SSL_FILETYPE_PEM);
		if (ret != 1) {
			rpctlscd_verbose_out("rpctls_setupcl_ssl: can't use "
			    "certificate file path=%s ret=%d\n", path, ret);
			SSL_CTX_free(ctx);
			return (NULL);
		}
		if (strlcpy(&path[len], "key.pem", rlen) != 7) {
			SSL_CTX_free(ctx);
			return (NULL);
		}
		ret = SSL_CTX_use_PrivateKey_file(ctx, path,
		    SSL_FILETYPE_PEM);
		if (ret != 1) {
			rpctlscd_verbose_out("rpctls_setupcl_ssl: Can't use "
			    "private key path=%s ret=%d\n", path, ret);
			SSL_CTX_free(ctx);
			return (NULL);
		}
	}
	if (rpctls_verify_cafile != NULL) {
		ret = SSL_CTX_load_verify_locations(ctx,
		    rpctls_verify_cafile, NULL);
		if (ret != 1) {
			rpctlscd_verbose_out("rpctls_setupcl_ssl: "
			    "Can't load verify locations\n");
			SSL_CTX_free(ctx);
			return (NULL);
		}
	}

	/* RPC-over-TLS must use TLSv1.3. */
#ifdef notyet
	flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
	    SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
#else
	flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_3;
#endif
	SSL_CTX_set_options(ctx, flags);
	return (ctx);
}

static SSL *
rpctls_connect(SSL_CTX *ctx, int s)
{
	SSL *ssl;
	X509 *cert;
	int ret;
	char *cp;

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		rpctlscd_verbose_out("rpctls_connect: "
		    "SSL_new failed\n");
		return (NULL);
	}
	if (SSL_set_fd(ssl, s) != 1) {
		rpctlscd_verbose_out("rpctls_connect: "
		    "SSL_set_fd failed\n");
		SSL_free(ssl);
		return (NULL);
	}
	ret = SSL_connect(ssl);
	if (ret != 1) {
		rpctlscd_verbose_out("rpctls_connect: "
		    "SSL_connect failed %d\n",
		    ret);
		SSL_free(ssl);
		return (NULL);
	}

	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		rpctlscd_verbose_out("rpctls_connect: get peer"
		    " certificate failed\n");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		return (NULL);
	}
	cp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	rpctlscd_verbose_out("rpctls_connect: cert subjectName=%s\n", cp);
	ret = SSL_get_verify_result(ssl);
	rpctlscd_verbose_out("rpctls_connect: get "
	    "verify result=%d\n", ret);
	if (ret == X509_V_OK && rpctls_comparehost &&
	    rpctls_checkhost(s, cert) != 1)
		ret = X509_V_ERR_HOSTNAME_MISMATCH;
	X509_free(cert);
	if (rpctls_verify && ret != X509_V_OK) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
		return (NULL);
	}

#ifdef notnow
	ret = BIO_get_ktls_send(SSL_get_wbio(ssl));
	fprintf(stderr, "ktls_send=%d\n", ret);
	ret = BIO_get_ktls_recv(SSL_get_rbio(ssl));
	fprintf(stderr, "ktls_recv=%d\n", ret);
#endif
	return (ssl);
}

/*
 * Check a client IP address against any host address in the
 * certificate.  Basically getpeername(2), getnameinfo(3) and
 * X509_check_host().
 */
static int
rpctls_checkhost(int s, X509 *cert)
{
	struct sockaddr *sad;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr_storage ad;
	char hostnam[NI_MAXHOST + 1], addrstr[INET6_ADDRSTRLEN + 1];
	const char *cp;
	socklen_t slen;
	int ret;

	sad = (struct sockaddr *)&ad;
	slen = sizeof(ad);
	if (getpeername(s, sad, &slen) < 0)
		return (0);
	switch (sad->sa_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)sad;
		cp = inet_ntop(sad->sa_family, &sin->sin_addr.s_addr,
		    addrstr, sizeof(addrstr));
		if (cp != NULL)
			rpctlscd_verbose_out("rpctls_checkhost: "
			    "peer ip %s\n", cp);
		if (getnameinfo((const struct sockaddr *)sad,
		    sizeof(struct sockaddr_in), hostnam,
		    sizeof(hostnam), NULL, 0, NI_NAMEREQD) != 0)
			return (0);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)sad;
		cp = inet_ntop(sad->sa_family, &sin6->sin6_addr,
		    addrstr, sizeof(addrstr));
		if (cp != NULL)
			rpctlscd_verbose_out("rpctls_checkhost: "
			    "peer ip %s\n", cp);
		if (getnameinfo((const struct sockaddr *)sad,
		    sizeof(struct sockaddr_in6), hostnam,
		    sizeof(hostnam), NULL, 0, NI_NAMEREQD) != 0)
			return (0);
		break;
	default:
		return (0);
	}
	rpctlscd_verbose_out("rpctls_checkhost: hostname %s\n",
	    hostnam);
	ret = X509_check_host(cert, hostnam, strlen(hostnam), 0, NULL);
	rpctlscd_verbose_out("rpctls_checkhost: X509_check_host ret=%d\n",
	    ret);
	return (ret);
}

