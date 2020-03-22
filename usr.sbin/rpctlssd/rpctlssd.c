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
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <err.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

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
#ifndef	_PREFERRED_CIPHERS
#define	_PREFERRED_CIPHERS	"SHA384:SHA256:!CAMELLIA"
#endif

static int		rpctls_debug_level;
static bool		rpctls_verbose;
static SSL_CTX		*rpctls_ctx = NULL;
static bool		rpctls_do_mutual = false;
static const char	*rpctls_verify_cafile = NULL;
static const char	*rpctls_verify_capath = NULL;
static const char	*rpctls_crlfile = NULL;
static const char	*rpctls_certdir = _PATH_CERTANDKEY;
static bool		rpctls_comparehost = false;
static uint64_t		rpctls_ssl_refno = 0;
static uint64_t		rpctls_ssl_sec = 0;
static uint64_t		rpctls_ssl_usec = 0;
static bool		rpctls_gothup = false;

/*
 * A linked list of all current "SSL *"s and socket "fd"s
 * for kernel RPC TLS connections is maintained.
 * The "refno" field is a unique 64bit value used to
 * identify which entry a kernel RPC upcall refers to.
 */
LIST_HEAD(ssl_list, ssl_entry);
struct ssl_entry {
	LIST_ENTRY(ssl_entry)	next;
	uint64_t		refno;
	int			s;
	SSL			*ssl;
};
static struct ssl_list	rpctls_ssllist;

static void		rpctlssd_terminate(int);
static SSL_CTX		*rpctls_setup_ssl(const char *certdir);
static SSL		*rpctls_server(SSL_CTX *ctx, int s,
			    uint32_t *flags);
static int		rpctls_checkhost(int s, X509 *cert);
static int		rpctls_loadfiles(SSL_CTX *ctx);
static void		rpctls_huphandler(int sig __unused);
static int cert_crl(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x);

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
	struct timeval tm;
	struct timezone tz;

	/* Get the time when this daemon is started. */
	gettimeofday(&tm, &tz);
	rpctls_ssl_sec = tm.tv_sec;
	rpctls_ssl_usec = tm.tv_usec;


	debug = 0;
	rpctls_verbose = false;
	while ((ch = getopt(argc, argv, "D:dhl:mp:rv")) != -1) {
		switch (ch) {
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
		case 'p':
			rpctls_verify_capath = optarg;
			break;
		case 'r':
			rpctls_crlfile = optarg;
			break;
		case 'v':
			rpctls_verbose = true;
			break;
		default:
			fprintf(stderr, "usage: %s "
			    "[-D certdir] [-d] [-h] "
			    "[-l CAfile] [-m] "
			    "[-p CApath] [-r CRLfile] "
			    "[-v]\n", argv[0]);
			exit(1);
		}
	}
	if (rpctls_do_mutual && rpctls_verify_cafile == NULL &&
	    rpctls_verify_capath == NULL)
		errx(1, "-m requires the -l <CAfile> and/or "
		    "-p <CApath> options");
	if (rpctls_comparehost && (!rpctls_do_mutual ||
	    (rpctls_verify_cafile == NULL && rpctls_verify_capath == NULL)))
		errx(1, "-h requires the -m and either the "
		    "-l <CAfile> or -p <CApath> options");

	if (modfind("krpc") < 0) {
		/* Not present in kernel, try loading it */
		if (kldload("krpc") < 0 || modfind("krpc") < 0)
			errx(1, "Kernel RPC is not available");
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
	signal(SIGHUP, rpctls_huphandler);

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
	rpctls_gothup = false;
	LIST_INIT(&rpctls_ssllist);

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
	struct ssl_entry *newslp;

	rpctlssd_verbose_out("rpctlsd_connect_svc: started\n");
	memset(result, 0, sizeof(*result));
	/* Get the socket fd from the kernel. */
	s = gssd_syscall("E");
rpctlssd_verbose_out("rpctlsd_connect_svc s=%d\n", s);
	if (s < 0)
		return (FALSE);

	/* Do the server side of a TLS handshake. */
	ssl = rpctls_server(rpctls_ctx, s, &flags);
	if (ssl == NULL)
		rpctlssd_verbose_out("rpctlssd_connect_svc: ssl "
		    "accept failed\n");
	else {
		rpctlssd_verbose_out("rpctlssd_connect_svc: "
		    "succeeded flags=0x%x\n", flags);
		result->flags = flags;
		result->sec = rpctls_ssl_sec;
		result->usec = rpctls_ssl_usec;
		result->ssl = ++rpctls_ssl_refno;
		/* Hard to believe this could ever wrap around.. */
		if (rpctls_ssl_refno == 0)
			result->ssl = ++rpctls_ssl_refno;
	}

	if (ssl == NULL) {
		/*
		 * For RPC-over-TLS, this upcall is expected
		 * to close off the socket.
		 */
		close(s);
		return (FALSE);
	}

	/* Maintain list of all current SSL *'s */
	newslp = malloc(sizeof(*newslp));
	newslp->ssl = ssl;
	newslp->s = s;
	newslp->refno = rpctls_ssl_refno;
	LIST_INSERT_HEAD(&rpctls_ssllist, newslp, next);
	return (TRUE);
}

bool_t
rpctlssd_disconnect_1_svc(struct rpctlssd_disconnect_arg *argp,
    void *result, struct svc_req *rqstp)
{
	struct ssl_entry *slp;

	slp = NULL;
	if (argp->sec == rpctls_ssl_sec && argp->usec ==
	    rpctls_ssl_usec) {
		LIST_FOREACH(slp, &rpctls_ssllist, next) {
			if (slp->refno == argp->ssl)
				break;
		}
	}

	if (slp != NULL) {
		rpctlssd_verbose_out("rpctlssd_disconnect fd=%d closed\n",
		    slp->s);
		LIST_REMOVE(slp, next);
		SSL_shutdown(slp->ssl);
		SSL_free(slp->ssl);
		/*
		 * For RPC-over-TLS, this upcall is expected
		 * to close off the socket.
		 */
		close(slp->s);
		free(slp);
	} else
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
	int err;
	char *cp;

	err = X509_STORE_CTX_get_error(x509_ctx);
	cp = (char *)X509_STORE_CTX_get_cert_crl(x509_ctx);
rpctlssd_verbose_out("verf cb pre=%d err=%d cercrl=%p\n", preverify_ok, err, cp);
	return (1);
}

static SSL_CTX *
rpctls_setup_ssl(const char *certdir)
{
	SSL_CTX *ctx;
	char path[PATH_MAX];
	size_t len, rlen;
	int ret;

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL) {
		rpctlssd_verbose_out("rpctls_setup_ssl: SSL_CTX_new failed\n");
		return (NULL);
	}
	SSL_CTX_set_ecdh_auto(ctx, 1);

	/*
	 * Set preferred ciphers, since KERN_TLS only supports a
	 * few of them.
	 */
	ret = SSL_CTX_set_cipher_list(ctx, _PREFERRED_CIPHERS);
	if (ret == 0) {
		rpctlssd_verbose_out("rpctls_setup_ssl: "
		    "SSL_CTX_set_cipher_list failed to set any ciphers\n");
		SSL_CTX_free(ctx);
		return (NULL);
	}

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
		ret = rpctls_loadfiles(ctx);
		if (ret == 0) {
			rpctlssd_verbose_out("rpctls_setup_ssl: "
			    "Load CAfile, CRLfile failed\n");
			SSL_CTX_free(ctx);
			return (NULL);
		}
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
	if (rpctls_gothup) {
		rpctls_gothup = false;
		ret = rpctls_loadfiles(ctx);
		if (ret == 0)
			rpctlssd_verbose_out("rpctls_server: Can't "
			    "load CAfile, CRLfile\n");
	}
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
			cp = X509_NAME_oneline(X509_get_issuer_name(cert),
			    NULL, 0);
			rpctlssd_verbose_out("rpctls_server: cert "
			    "issuerName=%s\n", cp);
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
int
rpctls_checkhost(int s, X509 *cert)
{
	struct sockaddr *sad;
	struct sockaddr_storage ad;
	char hostnam[NI_MAXHOST];
	socklen_t slen;
	int ret;

	sad = (struct sockaddr *)&ad;
	slen = sizeof(ad);
	if (getpeername(s, sad, &slen) < 0)
		return (0);
	if (getnameinfo((const struct sockaddr *)sad,
	    sad->sa_len, hostnam, sizeof(hostnam),
	    NULL, 0, NI_NUMERICHOST) == 0)
		rpctlssd_verbose_out("rpctls_checkhost: %s\n",
		    hostnam);
	if (getnameinfo((const struct sockaddr *)sad,
	    sad->sa_len, hostnam, sizeof(hostnam),
	    NULL, 0, NI_NAMEREQD) != 0)
		return (0);
	rpctlssd_verbose_out("rpctls_checkhost: DNS %s\n",
	    hostnam);
	ret = X509_check_host(cert, hostnam, strlen(hostnam), 0, NULL);
	return (ret);
}

/*
 * Load the CAfile (and optionally CRLfile) into the certificate
 * verification store.
 */
static int
rpctls_loadfiles(SSL_CTX *ctx)
{
	X509_STORE *certstore;
	X509_LOOKUP *certlookup;
	int ret;

	if (rpctls_verify_cafile != NULL ||
	    rpctls_verify_capath != NULL) {
		if (rpctls_crlfile != NULL) {
			certstore = SSL_CTX_get_cert_store(ctx);
			certlookup = X509_STORE_add_lookup(
			    certstore, X509_LOOKUP_file());
			ret = 0;
			if (certlookup != NULL)
				ret = X509_load_crl_file(certlookup,
				    rpctls_crlfile, X509_FILETYPE_PEM);
			if (ret != 0)
				ret = X509_STORE_set_flags(certstore,
				    X509_V_FLAG_CRL_CHECK |
				    X509_V_FLAG_CRL_CHECK_ALL);
			if (ret != 0)
{
X509_STORE_set_cert_crl(certstore, cert_crl);
				X509_STORE_set_verify_cb_func(
				    certstore, rpctls_verify_callback);
}
			if (ret == 0) {
				rpctlssd_verbose_out(
				    "rpctls_setup_ssl: Can't"
				    " load CRLfile=%s\n",
				    rpctls_crlfile);
				return (ret);
			}
		}
		ret = SSL_CTX_load_verify_locations(ctx,
		    rpctls_verify_cafile, rpctls_verify_capath);
		if (ret == 0) {
			rpctlssd_verbose_out("rpctls_setup_ssl: "
			    "Can't load verify locations\n");
			return (ret);
		}
		if (rpctls_verify_cafile != NULL)
			SSL_CTX_set_client_CA_list(ctx,
			    SSL_load_client_CA_file(
			    rpctls_verify_cafile));
	}
	return (1);
}

static void
rpctls_huphandler(int sig __unused)
{

	rpctls_gothup = true;
}

static int cert_crl(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x)
{
    X509_REVOKED *rev;
    int ret;

rpctlssd_verbose_out("in cert_crl\n");
    /*
     * The rules changed for this... previously if a CRL contained unhandled
     * critical extensions it could still be used to indicate a certificate
     * was revoked. This has since been changed since critical extensions can
     * change the meaning of CRL entries.
     */
#ifdef notnow
    if (!(ctx->param->flags & X509_V_FLAG_IGNORE_CRITICAL)
        && (crl->flags & EXFLAG_CRITICAL) &&
        !verify_cb_crl(ctx, X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION))
        return 0;
#endif
    /*
     * Look for serial number of certificate in CRL.  If found, make sure
     * reason is not removeFromCRL.
     */
    ret = X509_CRL_get0_by_cert(crl, &rev, x);
rpctlssd_verbose_out("get0 cert=%d\n", ret);
    if (ret != 0) {
#ifdef notnow
        if (rev->reason == CRL_REASON_REMOVE_FROM_CRL)
{ rpctls_verbose_out("ret 2\n");
            return 2;
}
        if (!verify_cb_crl(ctx, X509_V_ERR_CERT_REVOKED))
#endif
rpctlssd_verbose_out("ret 0\n");
            return 0;
    }

rpctlssd_verbose_out("ret 1\n");
    return 1;
}
