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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <err.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
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

#include "rpctlssd.h"

#ifndef _PATH_RPCTLSSDSOCK
#define _PATH_RPCTLSSDSOCK	"/var/run/rpctlssd.sock"
#define _PATH_RPCTLSSDS	"S/var/run/rpctlssd.sock"
#endif
#ifndef	_PATH_CERTANDKEY
#define	_PATH_CERTANDKEY	"/etc/rpctlssd/"
#endif

static int		rpctls_debug_level;
static bool		rpctls_verbose;
static int	testnossl;
static SSL_CTX		*rpctls_ctx = NULL;
static bool		rpctls_do_mutual = false;
static const char	*rpctls_verify_cafile = NULL;
static const char	*rpctls_client_cafiles = NULL;
static const char	*rpctls_certdir = _PATH_CERTANDKEY;
static bool		rpctls_comparehost = false;

static void		rpctlssd_terminate(int);
static SSL_CTX		*rpctls_setup_ssl(const char *certdir);
static SSL		*rpctls_server(SSL_CTX *ctx, int s,
			    uint32_t *flags);
static int		rpctls_checkhost(int s, X509 *cert);

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
	rpctls_verbose = false;
	testnossl = 0;
	while ((ch = getopt(argc, argv, "C:D:dhl:mtv")) != -1) {
		switch (ch) {
		case 'C':
			rpctls_client_cafiles = optarg;
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
		case 'm':
			rpctls_do_mutual = true;
			break;
		case 't':
			testnossl = 1;
			break;
		case 'v':
			rpctls_verbose = true;
			break;
		default:
			fprintf(stderr, "usage: %s [-C client_calist] "
			    "[-D certdir] [-d] [-h] "
			    "[-l verify_locations_file] "
			    "[-m] [-v]\n", argv[0]);
			exit(1);
			break;
		}
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

	rpctls_ctx = rpctls_setup_ssl(rpctls_certdir);
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
rpctlssd_null_1_svc(void *argp, void *result, struct svc_req *rqstp)
{

	rpctlssd_verbose_out("rpctlssd_null_svc: done\n");
	return (TRUE);
}

bool_t
rpctlssd_connect_1_svc(void *argp,
    struct rpctlssd_connect_res *result, struct svc_req *rqstp)
{
	int s;
	SSL *ssl;
	uint32_t flags;

	rpctlssd_verbose_out("rpctlsd_connect_svc: started\n");
	memset(result, 0, sizeof(*result));
	/* Get the socket fd from the kernel. */
	s = gssd_syscall("E");
rpctlssd_verbose_out("rpctlsd_connect_svc s=%d\n", s);
	if (s < 0)
		return (FALSE);

	if (testnossl == 0) {
		/* Do the server side of a TLS handshake. */
		ssl = rpctls_server(rpctls_ctx, s, &flags);
		if (ssl == NULL)
			rpctlssd_verbose_out("rpctlssd_connect_svc: ssl "
			    "accept failed\n");
		else {
			rpctlssd_verbose_out("rpctlssd_connect_svc: "
			    "succeeded flags=0x%x\n", flags);
			result->flags = flags;
		}
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

/* Allow the handshake to proceed. */
static int
rpctls_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{

	return (1);
}

static SSL_CTX *
rpctls_setup_ssl(const char *certdir)
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
	if (rpctls_do_mutual) {
		rpctlssd_verbose_out("rpctls_setup_ssl: set mutual\n");
		if (rpctls_verify_cafile != NULL) {
			ret = SSL_CTX_load_verify_locations(ctx,
			    rpctls_verify_cafile, NULL);
			if (ret != 1) {
				rpctlssd_verbose_out("rpctls_setup_ssl: "
				    "Can't load verify locations\n");
				SSL_CTX_free(ctx);
				return (NULL);
			}
		}
		if (rpctls_client_cafiles != NULL)
			SSL_CTX_set_client_CA_list(ctx,
			    SSL_load_client_CA_file(rpctls_client_cafiles));
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER,
		    rpctls_verify_callback);
	}
	return (ctx);
}

static SSL *
rpctls_server(SSL_CTX *ctx, int s, uint32_t *flags)
{
	SSL *ssl;
	X509 *cert;
	int ret;
	char *cp;

	*flags = 0;
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
		rpctlssd_verbose_out("rpctls_server: SSL_accept "
		    "failed ret=%d\n", ret);
		SSL_free(ssl);
		return (NULL);
	}
	*flags |= RPCTLS_FLAGS_HANDSHAKE;
	if (rpctls_do_mutual) {
		cert = SSL_get_peer_certificate(ssl);
		if (cert == NULL)
			rpctlssd_verbose_out("rpctls_server: "
			    "No peer certificate\n");
		else {
			cp = X509_NAME_oneline(X509_get_subject_name(cert),
			    NULL, 0);
			rpctlssd_verbose_out("rpctls_server: cert "
			    "subjectName=%s\n", cp);
			*flags |= RPCTLS_FLAGS_GOTCERT;
			ret = SSL_get_verify_result(ssl);
			rpctlssd_verbose_out("rpctls_server: get "
			    "verify result=%d\n", ret);
			if (ret ==
			    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
			    ret == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
				*flags |= RPCTLS_FLAGS_SELFSIGNED;
			else if (ret == X509_V_OK) {
				if (rpctls_comparehost) {
					ret = rpctls_checkhost(s, cert);
					if (ret != 1) {
						*flags |=
						    RPCTLS_FLAGS_DISABLED;
						rpctlssd_verbose_out(
						    "rpctls_server: "
						    "checkhost "
						    "failed\n");
					}
				}
				*flags |= RPCTLS_FLAGS_VERIFIED;
			}
			X509_free(cert);
		}
	}
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
			rpctlssd_verbose_out("rpctls_checkhost: "
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
			rpctlssd_verbose_out("rpctls_checkhost: "
			    "peer ip %s\n", cp);
		if (getnameinfo((const struct sockaddr *)sad,
		    sizeof(struct sockaddr_in6), hostnam,
		    sizeof(hostnam), NULL, 0, NI_NAMEREQD) != 0)
			return (0);
		break;
	default:
		return (0);
	}
	rpctlssd_verbose_out("rpctls_checkhost: hostname %s\n",
	    hostnam);
	ret = X509_check_host(cert, hostnam, strlen(hostnam), 0, NULL);
	rpctlssd_verbose_out("rpctls_checkhost: X509_check_host ret=%d\n",
	    ret);
	return (ret);
}

