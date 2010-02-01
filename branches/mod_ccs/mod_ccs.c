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

static _Bool ccs_print_encoded(apr_file_t *file, const char *string,
			       _Bool flush)
{
	apr_size_t len;
	while (1) {
		unsigned char c = *(const unsigned char *) string++;
		if (!c)
			break;
		if (c == '\\') {
			len = 2;
			if (apr_file_write(file, "\\\\", &len) != APR_SUCCESS
			    || len != 2)
				return 0;
		} else if (c > ' ' && c < 127) {
			len = 1;
			if (apr_file_write(file, &c , &len) != APR_SUCCESS
			    || len != 1)
				return 0;
		} else {
			char buffer[4] = { '\\', (c >> 6) + '0',
					   ((c >> 3) & 7) + '0',
					   (c & 7) + '0' };
			len = 4;
			if (apr_file_write(file, buffer, &len) != APR_SUCCESS
			    || len != 4)
				return 0;
		}
	}
	if (flush) {
		len = 1;
		return apr_file_write(file, "\n", &len) == APR_SUCCESS &&
			len == 1;
	}
	return 1;
}

static _Bool ccs_set_context(request_rec *r)
{
	apr_file_t *file = NULL;
	apr_status_t result;
	_Bool success;
	result = apr_file_open(&file, "/proc/ccs/self_domain",
			       APR_FOPEN_READ | APR_FOPEN_WRITE |
			       APR_FOPEN_BINARY | APR_BUFFERED, APR_OS_DEFAULT,
			       r->pool);
	if (result != APR_SUCCESS) {
		if (errno == ENOENT)
			return 1;
		return 0;
	}
	ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
		      "server='%s' filename='%s'", r->server->server_hostname,
		      r->filename);
	success = ccs_print_encoded(file, "/servername=", 0) &&
		ccs_print_encoded(file, r->server->server_hostname, 1) &&
		ccs_print_encoded(file, r->filename, 1);
	result = apr_file_close(file);
	return success && result == APR_SUCCESS;
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
