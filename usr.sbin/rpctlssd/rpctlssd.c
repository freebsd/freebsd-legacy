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
#include <libutil.h>
#include <netdb.h>
#include <pwd.h>
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

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "rpctlssd.h"

#ifndef _PATH_RPCTLSSDSOCK
#define _PATH_RPCTLSSDSOCK	"/var/run/rpctlssd.sock"
#endif
#ifndef	_PATH_CERTANDKEY
#define	_PATH_CERTANDKEY	"/etc/rpctlssd/"
#endif
#ifndef	_PATH_RPCTLSSDPID
#define	_PATH_RPCTLSSDPID	"/var/run/rpctlssd.pid"
#endif
#ifndef	_PREFERRED_CIPHERS
#define	_PREFERRED_CIPHERS	"AES128-GCM-SHA256"
#endif

static struct pidfh	*rpctls_pfh = NULL;
static int		rpctls_debug_level;
static bool		rpctls_verbose;
static SSL_CTX		*rpctls_ctx = NULL;
static bool		rpctls_do_mutual = false;
static const char	*rpctls_verify_cafile = NULL;
static const char	*rpctls_verify_capath = NULL;
static const char	*rpctls_crlfile = NULL;
static const char	*rpctls_certdir = _PATH_CERTANDKEY;
static bool		rpctls_comparehost = false;
static unsigned int	rpctls_wildcard = X509_CHECK_FLAG_NO_WILDCARDS;
static uint64_t		rpctls_ssl_refno = 0;
static uint64_t		rpctls_ssl_sec = 0;
static uint64_t		rpctls_ssl_usec = 0;
static bool		rpctls_gothup = false;
static bool		rpctls_cnuser = false;
static char		*rpctls_dnsname;
static const char	*rpctls_cnuseroid = "1.2.3.4.6.9";

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
			    uint32_t *flags, uint32_t *uidp,
			    int *ngrps, uint32_t *gidp);
static int		rpctls_gethost(int s, struct sockaddr *sad,
			    char *hostip, size_t hostlen);
static int		rpctls_checkhost(struct sockaddr *sad, X509 *cert);
static int		rpctls_loadcrlfile(SSL_CTX *ctx);
static int		rpctls_cnname(X509 *cert, uint32_t *uidp,
			    int *ngrps, uint32_t *gidp);
static char		*rpctls_getdnsname(char *dnsname);
static void		rpctls_huphandler(int sig __unused);

extern void		rpctlssd_1(struct svc_req *rqstp, SVCXPRT *transp);

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
	char hostname[MAXHOSTNAMELEN + 2];
	pid_t otherpid;

	/* Check that another rpctlssd isn't already running. */
	rpctls_pfh = pidfile_open(_PATH_RPCTLSSDPID, 0600, &otherpid);
	if (rpctls_pfh == NULL) {
		if (errno == EEXIST)
			errx(1, "rpctlssd already running, pid: %d.", otherpid);
		warn("cannot open or create pidfile");
	}

	if (modfind("ktls_ocf") < 0) {
		/* Not present in kernel, try loading it */
		if (kldload("ktls_ocf") < 0 || modfind("ktls_ocf") < 0)
			errx(1, "Cannot load ktls_ocf");
	}

	/* Get the time when this daemon is started. */
	gettimeofday(&tm, &tz);
	rpctls_ssl_sec = tm.tv_sec;
	rpctls_ssl_usec = tm.tv_usec;

	/* Set the dns name for the server. */
	rpctls_dnsname = rpctls_getdnsname(hostname);
	if (rpctls_dnsname == NULL) {
		strcpy(hostname, "@default.domain");
		rpctls_dnsname = hostname;
	}
fprintf(stderr, "dnsname=%s\n", rpctls_dnsname);

	debug = 0;
	rpctls_verbose = false;
	while ((ch = getopt(argc, argv, "D:dhl:n:mp:r:uvWw")) != -1) {
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
		case 'n':
			hostname[0] = '@';
			strlcpy(&hostname[1], optarg, MAXHOSTNAMELEN + 1);
			rpctls_dnsname = hostname;
			break;
		case 'p':
			rpctls_verify_capath = optarg;
			break;
		case 'r':
			rpctls_crlfile = optarg;
			break;
		case 'u':
			rpctls_cnuser = true;
			break;
		case 'v':
			rpctls_verbose = true;
			break;
		case 'W':
			if (rpctls_wildcard != X509_CHECK_FLAG_NO_WILDCARDS)
				errx(1, "options -w and -W are mutually "
				    "exclusive");
			rpctls_wildcard = X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS;
			break;
		case 'w':
			if (rpctls_wildcard != X509_CHECK_FLAG_NO_WILDCARDS)
				errx(1, "options -w and -W are mutually "
				    "exclusive");
			rpctls_wildcard = 0;
			break;
		default:
			fprintf(stderr, "usage: %s "
			    "[-D certdir] [-d] [-h] "
			    "[-l CAfile] [-m] "
			    "[-n domain_name] "
			    "[-p CApath] [-r CRLfile] "
			    "[-u] [-v] [-W] [-w]\n", argv[0]);
			exit(1);
		}
	}
	if (rpctls_do_mutual && rpctls_verify_cafile == NULL &&
	    rpctls_verify_capath == NULL)
		errx(1, "-m requires the -l <CAfile> and/or "
		    "-p <CApath> options");
	if (rpctls_comparehost && (!rpctls_do_mutual ||
	    (rpctls_verify_cafile == NULL && rpctls_verify_capath == NULL)))
		errx(1, "-h requires the -m plus the "
		    "-l <CAfile> and/or -p <CApath> options");
	if (!rpctls_comparehost && rpctls_wildcard !=
	    X509_CHECK_FLAG_NO_WILDCARDS)
		errx(1, "The -w or -W options require the -h option");
	if (rpctls_cnuser && (!rpctls_do_mutual ||
	    (rpctls_verify_cafile == NULL && rpctls_verify_capath == NULL)))
		errx(1, "-u requires the -m plus the "
		    "-l <CAfile> and/or -p <CApath> options");

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
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, rpctls_huphandler);

	pidfile_write(rpctls_pfh);

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

	rpctls_syscall(RPCTLS_SYSC_SRVSETPATH, _PATH_RPCTLSSDSOCK);
	svc_run();
	rpctls_syscall(RPCTLS_SYSC_SRVSHUTDOWN, "");

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
	int ngrps, s;
	SSL *ssl;
	uint32_t flags;
	struct ssl_entry *newslp;
	uint32_t uid;
	uint32_t *gidp;

	rpctlssd_verbose_out("rpctlsd_connect_svc: started\n");
	memset(result, 0, sizeof(*result));
	/* Get the socket fd from the kernel. */
	s = rpctls_syscall(RPCTLS_SYSC_SRVSOCKET, "");
rpctlssd_verbose_out("rpctlsd_connect_svc s=%d\n", s);
	if (s < 0)
		return (FALSE);

	/* Do the server side of a TLS handshake. */
	gidp = calloc(NGROUPS, sizeof(*gidp));
	ssl = rpctls_server(rpctls_ctx, s, &flags, &uid, &ngrps, gidp);
	if (ssl == NULL) {
		free(gidp);
		rpctlssd_verbose_out("rpctlssd_connect_svc: ssl "
		    "accept failed\n");
		/*
		 * For RPC-over-TLS, this upcall is expected
		 * to close off the socket.
		 */
		close(s);
		return (FALSE);
	} else {
		rpctlssd_verbose_out("rpctlssd_connect_svc: "
		    "succeeded flags=0x%x\n", flags);
		result->flags = flags;
		result->sec = rpctls_ssl_sec;
		result->usec = rpctls_ssl_usec;
		result->ssl = ++rpctls_ssl_refno;
		/* Hard to believe this could ever wrap around.. */
		if (rpctls_ssl_refno == 0)
			result->ssl = ++rpctls_ssl_refno;
		if ((flags & RPCTLS_FLAGS_CERTUSER) != 0) {
			result->uid = uid;
			result->gid.gid_len = ngrps;
			result->gid.gid_val = gidp;
		} else {
			result->uid = 0;
			result->gid.gid_len = 0;
			result->gid.gid_val = gidp;
		}
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
rpctlssd_handlerecord_1_svc(struct rpctlssd_handlerecord_arg *argp,
    struct rpctlssd_handlerecord_res *result, struct svc_req *rqstp)
{
	struct ssl_entry *slp;
	int ret;
	char junk;

	slp = NULL;
	if (argp->sec == rpctls_ssl_sec && argp->usec ==
	    rpctls_ssl_usec) {
		LIST_FOREACH(slp, &rpctls_ssllist, next) {
			if (slp->refno == argp->ssl)
				break;
		}
	}

	if (slp != NULL) {
		rpctlssd_verbose_out("rpctlssd_handlerecord fd=%d\n",
		    slp->s);
		/*
		 * An SSL_read() of 0 bytes should fail, but it should
		 * handle the non-application data record before doing so.
		 */
		ret = SSL_read(slp->ssl, &junk, 0);
		if (ret <= 0) {
			/* Check to see if this was a close alert. */
			ret = SSL_get_shutdown(slp->ssl);
rpctlssd_verbose_out("get_shutdown=%d\n", ret);
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
rpctlssd_disconnect_1_svc(struct rpctlssd_disconnect_arg *argp,
    struct rpctlssd_disconnect_res *result, struct svc_req *rqstp)
{
	struct ssl_entry *slp;
	int ret;

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
		ret = SSL_get_shutdown(slp->ssl);
rpctlssd_verbose_out("get_shutdown1=%d\n", ret);
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
rpctlssd_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result)
{
	rpctlssd_connect_res *res;

	if (xdr_result == (xdrproc_t)xdr_rpctlssd_connect_res) {
		res = (rpctlssd_connect_res *)result;
		if (res->gid.gid_val != NULL)
			free(res->gid.gid_val);
	}
	return (TRUE);
}

static void
rpctlssd_terminate(int sig __unused)
{

	rpctls_syscall(RPCTLS_SYSC_SRVSHUTDOWN, "");
	pidfile_remove(rpctls_pfh);
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
		if (rpctls_verify_cafile != NULL ||
		    rpctls_verify_capath != NULL) {
			if (rpctls_crlfile != NULL) {
				ret = rpctls_loadcrlfile(ctx);
				if (ret == 0) {
					rpctlssd_verbose_out("rpctls_setup_ssl:"
					    " Load CRLfile failed\n");
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
				rpctlssd_verbose_out("rpctls_setup_ssl: "
				    "Can't load verify locations\n");
				SSL_CTX_free(ctx);
				return (NULL);
			}
			if (rpctls_verify_cafile != NULL)
				SSL_CTX_set_client_CA_list(ctx,
				    SSL_load_client_CA_file(
			    rpctls_verify_cafile));
		}
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER,
		    rpctls_verify_callback);
	}
	return (ctx);
}

static SSL *
rpctls_server(SSL_CTX *ctx, int s, uint32_t *flags, uint32_t *uidp,
    int *ngrps, uint32_t *gidp)
{
	SSL *ssl;
	X509 *cert;
	struct sockaddr *sad;
	struct sockaddr_storage ad;
	char hostnam[NI_MAXHOST];
	int gethostret, ret;
	char *cp, *cp2;

	*flags = 0;
	sad = (struct sockaddr *)&ad;
	if (rpctls_gothup) {
		rpctls_gothup = false;
		ret = rpctls_loadcrlfile(ctx);
		if (ret == 0)
			rpctlssd_verbose_out("rpctls_server: Can't "
			    "reload CRLfile\n");
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
		if (cert != NULL) {
			gethostret = rpctls_gethost(s, sad, hostnam,
			    sizeof(hostnam));
			if (gethostret == 0)
				hostnam[0] = '\0';
			cp2 = X509_NAME_oneline(
			    X509_get_subject_name(cert), NULL, 0);
rpctlssd_verbose_out("%s\n", cp2);
			*flags |= RPCTLS_FLAGS_GOTCERT;
			ret = SSL_get_verify_result(ssl);
			if (ret != X509_V_OK) {
				cp = X509_NAME_oneline(
				    X509_get_issuer_name(cert), NULL, 0);
				if (rpctls_debug_level == 0)
					syslog(LOG_INFO | LOG_DAEMON,
					    "rpctls_server: client IP %s "
					    "issuerName=%s subjectName=%s"
					    " verify failed %s\n", hostnam,
					    cp, cp2,
					    X509_verify_cert_error_string(ret));
				else
					fprintf(stderr,
					    "rpctls_server: client IP %s "
					    "issuerName=%s subjectName=%s"
					    " verify failed %s\n", hostnam,
					    cp, cp2,
					    X509_verify_cert_error_string(ret));
			}
			if (ret ==
			    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
			    ret == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
				*flags |= RPCTLS_FLAGS_SELFSIGNED;
			else if (ret == X509_V_OK) {
				if (rpctls_comparehost) {
					ret = 0;
					if (gethostret != 0)
						ret = rpctls_checkhost(sad,
						    cert);
					if (ret != 1) {
						*flags |=
						    RPCTLS_FLAGS_DISABLED;
						rpctlssd_verbose_out(
						    "rpctls_server: "
						    "checkhost "
						    "failed\n");
					}
				}
				if (rpctls_cnuser) {
					ret = rpctls_cnname(cert, uidp,
					    ngrps, gidp);
					if (ret != 0)
						*flags |= RPCTLS_FLAGS_CERTUSER;
				}
				*flags |= RPCTLS_FLAGS_VERIFIED;
			}
			X509_free(cert);
		} else
			rpctlssd_verbose_out("rpctls_server: "
			    "No peer certificate\n");
	}

	/* Check to see that ktls is working for the connection. */
	ret = BIO_get_ktls_send(SSL_get_wbio(ssl));
	rpctlssd_verbose_out("rpctls_server: BIO_get_ktls_send=%d\n", ret);
	if (ret != 0) {
		ret = BIO_get_ktls_recv(SSL_get_rbio(ssl));
		rpctlssd_verbose_out("rpctls_server: BIO_get_ktls_recv=%d\n", ret);
	}
	if (ret == 0) {
		if (rpctls_debug_level == 0)
			syslog(LOG_ERR, "ktls not working");
		else
			fprintf(stderr, "ktls not working\n");
		/*
		 * The handshake has completed, so all that can be
		 * done is disable the connection.
		 */
		*flags |= RPCTLS_FLAGS_DISABLED;
	}

	return (ssl);
}

/*
 * Get the client's IP address.
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
		rpctlssd_verbose_out("rpctls_gethost: %s\n",
		    hostip);
		ret = 1;
	}
	return (ret);
}

/*
 * Check a client IP address against any host address in the
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
	rpctlssd_verbose_out("rpctls_checkhost: DNS %s\n",
	    hostnam);
	ret = X509_check_host(cert, hostnam, strlen(hostnam),
	    rpctls_wildcard, NULL);
	return (ret);
}

/*
 * Acquire the dnsname for this server.
 */
static char *
rpctls_getdnsname(char *hostname)
{
	char *cp, *dnsname;
	struct addrinfo *aip, hints;
	int error;

	dnsname = NULL;
	if (gethostname(hostname, MAXHOSTNAMELEN) == 0) {
		if ((cp = strchr(hostname, '.')) != NULL &&
		    *(cp + 1) != '\0') {
			*cp = '@';
			dnsname = cp;
		} else {
			memset((void *)&hints, 0, sizeof (hints));
			hints.ai_flags = AI_CANONNAME;
			error = getaddrinfo(hostname, NULL, &hints, &aip);
			if (error == 0) {
				if (aip->ai_canonname != NULL &&
				    (cp = strchr(aip->ai_canonname, '.')) !=
				    NULL && *(cp + 1) != '\0') {
					hostname[0] = '@';
					strlcpy(&hostname[1], cp + 1,
					    MAXHOSTNAMELEN + 1);
					dnsname = hostname;
				}
				freeaddrinfo(aip);
			}
		}
	}
	return (dnsname);
}

/*
 * Check a commonName to see if it maps to "user@domain" and
 * acquire a <uid, gidlist> for it if it does.
 */
static int
rpctls_cnname(X509 *cert, uint32_t *uidp, int *ngrps, uint32_t *gidp)
{
	char *cp, usern[1024 + 1];
	struct passwd *pwd;
	gid_t gids[NGROUPS];
	int i;
	GENERAL_NAMES *genlist;
	GENERAL_NAME *genname;
	OTHERNAME *val;

	/* First, find the otherName in the subjectAltName. */
	genlist = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
rpctlssd_verbose_out("genlist=%p\n", genlist);
	if (genlist == NULL)
		return (0);
	val = NULL;
	for (i = 0; i < sk_GENERAL_NAME_num(genlist); i++) {
		genname = sk_GENERAL_NAME_value(genlist, i);
		if (genname->type != GEN_OTHERNAME)
			continue;
		val = genname->d.otherName;
		break;
	}
	if (val == NULL)
		return (0);
rpctlssd_verbose_out("fnd type=0x%x len=%d anstyp=0x%x data=%s\n", val->value->type, val->value->value.utf8string->length, val->value->value.utf8string->type, val->value->value.utf8string->data);

	/* Check to see that it is the correct OID. */
	i = i2t_ASN1_OBJECT(usern, sizeof(usern), val->type_id);
rpctlssd_verbose_out("obj=%d str=%s\n", i,  usern);
	if (i != strlen(rpctls_cnuseroid) || memcmp(usern, rpctls_cnuseroid,
	    i) != 0) {
		rpctlssd_verbose_out("rpctls_cnname: invalid cnuser "
		    "oid len=%d val=%s\n", i, usern);
		return (0);
	}

	/* Sanity check the otherName. */
	if (val->value->type != V_ASN1_UTF8STRING ||
	    val->value->value.utf8string->length < 3 ||
	    val->value->value.utf8string->length > sizeof(usern) - 1) {
		rpctlssd_verbose_out("rpctls_cnname: invalid cnuser "
		    "type=%d\n", val->value->type);
		return (0);
	}

	/* Look for a "user" in the otherName */
	memcpy(usern, val->value->value.utf8string->data,
	    val->value->value.utf8string->length);
	usern[val->value->value.utf8string->length] = '\0';
	rpctlssd_verbose_out("rpctls_cnname: userstr %s\n", usern);

	/* Now, look for the @dnsname suffix in the commonName. */
	cp = strcasestr(usern, rpctls_dnsname);
	if (cp == NULL)
		return (0);
rpctlssd_verbose_out("dns=%s\n", cp);
	if (*(cp + strlen(rpctls_dnsname)) != '\0')
		return (0);
	*cp = '\0';

	/* See if the "user" is in the passwd database. */
rpctlssd_verbose_out("user=%s\n", usern);
	pwd = getpwnam(usern);
	if (pwd == NULL)
		return (0);
rpctlssd_verbose_out("pwname=%s\n", pwd->pw_name);
	*uidp = pwd->pw_uid;
	*ngrps = NGROUPS;
	if (getgrouplist(pwd->pw_name, pwd->pw_gid, gids, ngrps) < 0)
		return (0);
	for (i = 0; i < *ngrps; i++)
		gidp[i] = gids[i];
	return (1);
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
			rpctlssd_verbose_out(
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

