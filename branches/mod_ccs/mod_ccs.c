#include "httpd.h"
#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_thread_proc.h"
#include "ap_listen.h"
#include "ap_mpm.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"
#include <unistd.h>

static _Bool ccs_set_context(request_rec *r)
{
	const int fd = open("/proc/ccs/.transition", O_WRONLY);
	int len;
	_Bool success = 0;
	if (fd == EOF)
		return errno == ENOENT ? 1 : 0;
	{ /* Transit domain by virtual host's name. */
		char *buffer;
		char *name = r->server->server_hostname;
		len = strlen(name) + 32;
		buffer = calloc(len, 1);
		if (buffer) {
			snprintf(buffer, len - 1, "servername=%s",
				 name);
			len = strlen(buffer) + 1;
			success = write(fd, buffer, len) == len;
			free(buffer);
		}
		if (!success)
			goto out;
	}
	success = 0;
	{ /* Transit domain by requested pathname. */
		const char *filename = r->filename;
		if (!strncmp(filename, "/var/www/cgi-bin/", 17)) {
			char *buffer;
			len = strlen(filename) + 32;
			buffer = calloc(len, 1);
			if (buffer) {
				snprintf(buffer, len - 1,
					 "appname=%s", filename);
				len = strlen(buffer) + 1;
				success = write(fd, buffer, len) == len;
				free(buffer);
			}
		} else if (!strncmp(filename, "/usr/share/horde/", 17)) {
			success = write(fd, "appname=horde", 14) == 14;
		} else {
			success = write(fd, "default", 8) == 8;
		}
	}
 out:
	return close(fd) == 0 && success;
}

static int __thread volatile am_worker = 0;

static void *APR_THREAD_FUNC ccs_worker_handler(apr_thread_t *thread,
						void *data)
{
	request_rec *r = (request_rec *) data;
	int result;
	/* marks as the current context is worker thread */
	am_worker = 1;
	/* set security context */
	if (!ccs_set_context(r))
		apr_thread_exit(thread, HTTP_INTERNAL_SERVER_ERROR);
	/* invoke content handler */
	result = ap_run_handler(r);
	if (result == DECLINED)
		result = HTTP_INTERNAL_SERVER_ERROR;
	apr_thread_exit(thread, result);
	return NULL;
}

static int ccs_handler(request_rec *r)
{
	apr_threadattr_t *thread_attr = NULL;
	apr_thread_t *thread = NULL;
	apr_status_t rv;
	apr_status_t thread_rv;
	if (am_worker)
		return DECLINED;
	apr_threadattr_create(&thread_attr, r->pool);
	apr_threadattr_detach_set(thread_attr, 0);
	rv = apr_thread_create(&thread, thread_attr, ccs_worker_handler, r,
			       r->pool);
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
			      "Unable to launch a one-time worker thread");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	rv = apr_thread_join(&thread_rv, thread);
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
			      "Unable to join the one-time worker thread");
		r->connection->aborted = 1;
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	return thread_rv;
}

static void ccs_hooks(apr_pool_t *p)
{
	ap_hook_handler(ccs_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

module AP_MODULE_DECLARE_DATA ccs_module = {
	STANDARD20_MODULE_STUFF,
	NULL,                   /* create per-directory config */
	NULL,                   /* merge per-directory config */
	NULL,                   /* server config creator */
	NULL,                   /* server config merger */
	NULL,                   /* command table */
	ccs_hooks,              /* set up other hooks */
};
