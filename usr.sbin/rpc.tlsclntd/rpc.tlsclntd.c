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
#include <sys/queue.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <err.h>
#include <getopt.h>
#include <libutil.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rpc/rpc.h>
#include <rpc/rpc_com.h>
#include <rpc/rpcsec_tls.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "rpctlscd.h"

#ifndef _PATH_RPCTLSCDSOCK
#define _PATH_RPCTLSCDSOCK	"/var/run/rpc.tlsclntd.sock"
#endif
#ifndef	_PATH_CERTANDKEY
#define	_PATH_CERTANDKEY	"/etc/rpc.tlsclntd/"
#endif
#ifndef	_PATH_RPCTLSCDPID
#define	_PATH_RPCTLSCDPID	"/var/run/rpc.tlsclntd.pid"
#endif
#ifndef	_PREFERRED_CIPHERS
#define	_PREFERRED_CIPHERS	"AES128-GCM-SHA256"
#endif

static struct pidfh	*rpctls_pfh = NULL;
static int		rpctls_debug_level;
static bool		rpctls_verbose;
static SSL_CTX		*rpctls_ctx = NULL;
static const char	*rpctls_verify_cafile = NULL;
static const char	*rpctls_verify_capath = NULL;
static const char	*rpctls_crlfile = NULL;
static const char	*rpctls_certdir = _PATH_CERTANDKEY;
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

static void		rpctlscd_terminate(int);
static SSL_CTX		*rpctls_setupcl_ssl(bool cert);
static SSL		*rpctls_connect(SSL_CTX *ctx, int s);
static int		rpctls_gethost(int s, struct sockaddr *sad,
			    char *hostip, size_t hostlen);
static int		rpctls_checkhost(struct sockaddr *sad, X509 *cert);
static int		rpctls_loadcrlfile(SSL_CTX *ctx);
static void		rpctls_huphandler(int sig __unused);

extern void rpctlscd_1(struct svc_req *rqstp, SVCXPRT *transp);

static struct option longopts[] = {
	{ "certdir",		required_argument,	NULL,	'D' },
	{ "debuglevel",		no_argument,		NULL,	'd' },
	{ "verifylocs",		required_argument,	NULL,	'l' },
	{ "mutualverf",		no_argument,		NULL,	'm' },
	{ "verifydir",		required_argument,	NULL,	'p' },
	{ "crl",		required_argument,	NULL,	'r' },
	{ "verbose",		no_argument,		NULL,	'v' },
	{ NULL,			0,			NULL,	0  }
};

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
	struct timeval tm;
	struct timezone tz;
	pid_t otherpid;

	/* Check that another rpctlscd isn't already running. */
	rpctls_pfh = pidfile_open(_PATH_RPCTLSCDPID, 0600, &otherpid);
	if (rpctls_pfh == NULL) {
		if (errno == EEXIST)
			errx(1, "rpctlscd already running, pid: %d.", otherpid);
		warn("cannot open or create pidfile");
	}

	if (modfind("ktls_ocf") < 0) {
		/* Not present in kernel, try loading it */
		if (kldload("ktls_ocf") < 0 || modfind("ktls_ocf") < 0)
			errx(1, "Cannot load ktls_ocf");
	}
	if (modfind("aesni") < 0) {
		/* Not present in kernel, try loading it */
		kldload("aesni");
	}

	/* Get the time when this daemon is started. */
	gettimeofday(&tm, &tz);
	rpctls_ssl_sec = tm.tv_sec;
	rpctls_ssl_usec = tm.tv_usec;

	rpctls_verbose = false;
	cert = false;
	while ((ch = getopt_long(argc, argv, "D:dl:mp:r:v", longopts, NULL)) !=
	    -1) {
		switch (ch) {
		case 'D':
			rpctls_certdir = optarg;
			break;
		case 'd':
			rpctls_debug_level++;
			break;
		case 'l':
			rpctls_verify_cafile = optarg;
			break;
		case 'm':
			cert = true;
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
			    "[-D/--certdir certdir] [-d/--debuglevel] "
			    "[-l/--verifylocs CAfile] [-m/--mutualverf] "
			    "[-p/--verifydir CApath] [-r/--crl CRLfile] "
			    "[-v/--verbose]\n", argv[0]);
			exit(1);
			break;
		}
	}
	if (rpctls_crlfile != NULL && rpctls_verify_cafile == NULL &&
	    rpctls_verify_capath == NULL)
		errx(1, "-r requires the -l <CAfile> and/or "
		    "-p <CApath> options");

	if (modfind("krpc") < 0) {
		/* Not present in kernel, try loading it */
		if (kldload("krpc") < 0 || modfind("krpc") < 0)
			errx(1, "Kernel RPC is not available");
	}

	/*
	 * Set up the SSL_CTX *.
	 * Do it now, before daemonizing, in case the private key
	 * is encrypted and requires a passphrase to be entered.
	 */
	rpctls_ctx = rpctls_setupcl_ssl(cert);
	if (rpctls_ctx == NULL) {
		if (rpctls_debug_level == 0) {
			syslog(LOG_ERR, "Can't set up TSL context");
			exit(1);
		}
		err(1, "Can't set up TSL context");
	}
	LIST_INIT(&rpctls_ssllist);

	if (!rpctls_debug_level) {
		if (daemon(0, 0) != 0)
			err(1, "Can't daemonize");
		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
	}
	signal(SIGTERM, rpctlscd_terminate);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, rpctls_huphandler);

	pidfile_write(rpctls_pfh);

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

	rpctls_syscall(RPCTLS_SYSC_CLSETPATH, _PATH_RPCTLSCDSOCK);
	svc_run();
	rpctls_syscall(RPCTLS_SYSC_CLSHUTDOWN, "");

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
rpctlscd_connect_1_svc(void *argp,
    struct rpctlscd_connect_res *result, struct svc_req *rqstp)
{
	int s;
	bool_t res;
	SSL *ssl;
	char buf[1024];
	ssize_t siz, ret;
	struct ssl_entry *newslp;

	rpctlscd_verbose_out("rpctlsd_connect: started\n");
	/* Get the socket fd from the kernel. */
	s = rpctls_syscall(RPCTLS_SYSC_CLSOCKET, "");
rpctlscd_verbose_out("rpctlsd_connect s=%d\n", s);
	if (s < 0) {
		result->reterr = RPCTLSERR_NOSOCKET;
		return (TRUE);
	}

	/* Do a TLS connect handshake. */
	ssl = rpctls_connect(rpctls_ctx, s);
	if (ssl == NULL) {
		rpctlscd_verbose_out("rpctlsd_connect: can't do TLS "
		    "handshake\n");
		result->reterr = RPCTLSERR_NOSSL;
	} else {
		result->reterr = RPCTLSERR_OK;
		result->sec = rpctls_ssl_sec;
		result->usec = rpctls_ssl_usec;
		result->ssl = ++rpctls_ssl_refno;
		/* Hard to believe this will ever wrap around.. */
		if (rpctls_ssl_refno == 0)
			result->ssl = ++rpctls_ssl_refno;
	}

	if (ssl == NULL) {
		/*
		 * For RPC-over-TLS, this upcall is expected
		 * to close off the socket.
		 */
		close(s);
		return (TRUE);
	}

	/* Maintain list of all current SSL *'s */
	newslp = malloc(sizeof(*newslp));
	newslp->refno = rpctls_ssl_refno;
	newslp->s = s;
	newslp->ssl = ssl;
	LIST_INSERT_HEAD(&rpctls_ssllist, newslp, next);
	return (TRUE);
}

bool_t
rpctlscd_handlerecord_1_svc(struct rpctlscd_handlerecord_arg *argp,
    struct rpctlscd_handlerecord_res *result, struct svc_req *rqstp)
{
	struct ssl_entry *slp;
	int ret;
	char junk;

rpctlscd_verbose_out("handlerec sslref=%jx\n", (uintmax_t)slp->refno);
	slp = NULL;
	if (argp->sec == rpctls_ssl_sec && argp->usec ==
	    rpctls_ssl_usec) {
		LIST_FOREACH(slp, &rpctls_ssllist, next) {
			if (slp->refno == argp->ssl)
				break;
		}
	}

	if (slp != NULL) {
		rpctlscd_verbose_out("rpctlscd_handlerecord fd=%d\n",
		    slp->s);
		/*
		 * An SSL_read() of 0 bytes should fail, but it should
		 * handle the non-application data record before doing so.
		 */
		ret = SSL_read(slp->ssl, &junk, 0);
		if (ret <= 0) {
			/* Check to see if this was a close alert. */
			ret = SSL_get_shutdown(slp->ssl);
rpctlscd_verbose_out("get_shutdown2=%d\n", ret);
			if ((ret & (SSL_SENT_SHUTDOWN |
			    SSL_RECEIVED_SHUTDOWN)) == SSL_RECEIVED_SHUTDOWN)
				SSL_shutdown(slp->ssl);
		} else {
			if (rpctls_debug_level == 0)
				syslog(LOG_ERR, "SSL_read returned %d", ret);
			else
				fprintf(stderr, "SSL_read returned %d\n", ret);
		}
		result->reterr = RPCTLSERR_OK;
	} else
		result->reterr = RPCTLSERR_NOSSL;
	return (TRUE);
}

bool_t
rpctlscd_disconnect_1_svc(struct rpctlscd_disconnect_arg *argp,
    struct rpctlscd_disconnect_res *result, struct svc_req *rqstp)
{
	struct ssl_entry *slp;
	int ret;

rpctlscd_verbose_out("disconnect refno=%jx\n", (uintmax_t)slp->refno);
	slp = NULL;
	if (argp->sec == rpctls_ssl_sec && argp->usec ==
	    rpctls_ssl_usec) {
		LIST_FOREACH(slp, &rpctls_ssllist, next) {
			if (slp->refno == argp->ssl)
				break;
		}
	}

	if (slp != NULL) {
		rpctlscd_verbose_out("rpctlscd_disconnect: fd=%d closed\n",
		    slp->s);
		LIST_REMOVE(slp, next);
		ret = SSL_get_shutdown(slp->ssl);
rpctlscd_verbose_out("get_shutdown0=%d\n", ret);
		/*
		 * Do an SSL_shutdown() unless a close alert has
		 * already been sent.
		 */
		if ((ret & SSL_SENT_SHUTDOWN) == 0)
			SSL_shutdown(slp->ssl);
		SSL_free(slp->ssl);
		/*
		 * For RPC-over-TLS, this upcall is expected
		 * to close off the socket.
		 */
		shutdown(slp->s, SHUT_WR);
		close(slp->s);
		free(slp);
		result->reterr = RPCTLSERR_OK;
	} else
		result->reterr = RPCTLSERR_NOCLOSE;
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

	rpctls_syscall(RPCTLS_SYSC_CLSHUTDOWN, "");
	pidfile_remove(rpctls_pfh);
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

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL) {
		rpctlscd_verbose_out("rpctls_setupcl_ssl: SSL_CTX_new "
		    "failed\n");
		return (NULL);
	}
	SSL_CTX_set_ecdh_auto(ctx, 1);

	/*
	 * Set preferred ciphers, since KERN_TLS only supports a
	 * few of them.
	 */
	ret = SSL_CTX_set_cipher_list(ctx, _PREFERRED_CIPHERS);
	if (ret == 0) {
		rpctlscd_verbose_out("rpctls_setupcl_ssl: "
		    "SSL_CTX_set_cipher_list failed to set any ciphers\n");
		SSL_CTX_free(ctx);
		return (NULL);
	}

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
	if (rpctls_verify_cafile != NULL || rpctls_verify_capath != NULL) {
		if (rpctls_crlfile != NULL) {
			ret = rpctls_loadcrlfile(ctx);
			if (ret == 0) {
				rpctlscd_verbose_out("rpctls_setupcl_ssl: "
				    "Load CRLfile failed\n");
				SSL_CTX_free(ctx);
				return (NULL);
			}
		}
#if OPENSSL_VERSION_NUMBER >= 0x30000000
		ret = 1;
		if (rpctls_verify_cafile != NULL)
			ret = SSL_CTX_load_verify_file(ctx,
			    rpctls_verify_cafile);
		if (ret != 0 && rpctls_verify_capath != NULL)
			ret = SSL_CTX_load_verify_dir(ctx,
			    rpctls_verify_capath);
#else
		ret = SSL_CTX_load_verify_locations(ctx,
		    rpctls_verify_cafile, rpctls_verify_capath);
#endif
		if (ret == 0) {
			rpctlscd_verbose_out("rpctls_setupcl_ssl: "
			    "Can't load verify locations\n");
			SSL_CTX_free(ctx);
			return (NULL);
		}
		/*
		 * The man page says that the
		 * SSL_CTX_set0_CA_list() call is not normally
		 * needed, but I believe it is harmless.
		 */
		if (rpctls_verify_cafile != NULL)
			SSL_CTX_set0_CA_list(ctx,
			    SSL_load_client_CA_file(rpctls_verify_cafile));
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
	struct sockaddr *sad;
	struct sockaddr_storage ad;
	char hostnam[NI_MAXHOST];
	int gethostret, ret;
	char *cp, *cp2;

	if (rpctls_gothup) {
		rpctls_gothup = false;
		ret = rpctls_loadcrlfile(ctx);
		if (ret == 0)
			rpctlscd_verbose_out("rpctls_connect: Can't "
			    "reload CRLfile\n");
	}
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
rpctlscd_verbose_out("at SSL_connect\n");
	ret = SSL_connect(ssl);
rpctlscd_verbose_out("aft SSL_connect ret=%d\n", ret);
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
		SSL_free(ssl);
		return (NULL);
	}
	gethostret = rpctls_gethost(s, sad, hostnam, sizeof(hostnam));
	if (gethostret == 0)
		hostnam[0] = '\0';
	ret = SSL_get_verify_result(ssl);
	if (ret == X509_V_OK && (rpctls_verify_cafile != NULL ||
	    rpctls_verify_capath != NULL) && (gethostret == 0 ||
	    rpctls_checkhost(sad, cert) != 1))
		ret = X509_V_ERR_HOSTNAME_MISMATCH;
	X509_free(cert);
	if (ret != X509_V_OK && (rpctls_verify_cafile != NULL ||
	    rpctls_verify_capath != NULL)) {
		if (ret != X509_V_OK) {
			cp = X509_NAME_oneline(X509_get_issuer_name(cert),
			    NULL, 0);
			cp2 = X509_NAME_oneline(X509_get_subject_name(cert),
			    NULL, 0);
			if (rpctls_debug_level == 0)
				syslog(LOG_INFO | LOG_DAEMON,
				    "rpctls_connect: client IP %s "
				    "issuerName=%s subjectName=%s verify "
				    "failed %s\n", hostnam, cp, cp2,
				    X509_verify_cert_error_string(ret));
			else
				fprintf(stderr,
				    "rpctls_connect: client IP %s "
				    "issuerName=%s subjectName=%s verify "
				    "failed %s\n", hostnam, cp, cp2,
				    X509_verify_cert_error_string(ret));
		}
		SSL_free(ssl);
		return (NULL);
	}

	/* Check to see if ktls is enabled on the connection. */
	ret = BIO_get_ktls_send(SSL_get_wbio(ssl));
	rpctlscd_verbose_out("rpctls_connect: BIO_get_ktls_send=%d\n", ret);
	if (ret != 0) {
		ret = BIO_get_ktls_recv(SSL_get_rbio(ssl));
		rpctlscd_verbose_out("rpctls_connect: BIO_get_ktls_recv=%d\n", ret);
	}
	if (ret == 0) {
		if (rpctls_debug_level == 0)
			syslog(LOG_ERR, "ktls not working\n");
		else
			fprintf(stderr, "ktls not working\n");
		SSL_free(ssl);
		return (NULL);
	}

	return (ssl);
}

/*
 * Get the server's IP address.
 */
static int
rpctls_gethost(int s, struct sockaddr *sad, char *hostip, size_t hostlen)
{
	socklen_t slen;
	int ret;

	slen = sizeof(struct sockaddr_storage);
	if (getpeername(s, sad, &slen) < 0)
		return (0);
	ret = 0;
	if (getnameinfo((const struct sockaddr *)sad,
	    sad->sa_len, hostip, hostlen,
	    NULL, 0, NI_NUMERICHOST) == 0) {
		rpctlscd_verbose_out("rpctls_gethost: %s\n",
		    hostip);
		ret = 1;
	}
	return (ret);
}

/*
 * Check a server IP address against any host address in the
 * certificate.  Basically getnameinfo(3) and
 * X509_check_host().
 */
static int
rpctls_checkhost(struct sockaddr *sad, X509 *cert)
{
	char hostnam[NI_MAXHOST];
	int ret;

	if (getnameinfo((const struct sockaddr *)sad,
	    sad->sa_len, hostnam, sizeof(hostnam),
	    NULL, 0, NI_NAMEREQD) != 0)
		return (0);
	rpctlscd_verbose_out("rpctls_checkhost: DNS %s\n",
	    hostnam);
	ret = X509_check_host(cert, hostnam, strlen(hostnam),
	    X509_CHECK_FLAG_NO_WILDCARDS, NULL);
	return (ret);
}

/*
 * (re)load the CRLfile into the certificate verification store.
 */
static int
rpctls_loadcrlfile(SSL_CTX *ctx)
{
	X509_STORE *certstore;
	X509_LOOKUP *certlookup;
	int ret;

	if ((rpctls_verify_cafile != NULL ||
	    rpctls_verify_capath != NULL) &&
	    rpctls_crlfile != NULL) {
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
		if (ret == 0) {
			rpctlscd_verbose_out(
			    "rpctls_loadcrlfile: Can't"
			    " load CRLfile=%s\n",
			    rpctls_crlfile);
			return (ret);
		}
	}
	return (1);
}

static void
rpctls_huphandler(int sig __unused)
{

	rpctls_gothup = true;
}

