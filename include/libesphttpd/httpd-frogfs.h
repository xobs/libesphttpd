#ifndef HTTPDFROGFS_H
#define HTTPDFROGFS_H

#ifdef linux
#include <libesphttpd/linux.h>
#else
#include <libesphttpd/esp.h>  // for sdkconfig.h
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_ESPHTTPD_USE_FROGFS
#include "frogfs/frogfs.h"
#include "httpd.h"
/**
 * The template substitution callback.
 * Returns CGI_MORE if more should be sent within the token, CGI_DONE otherwise.
 */
typedef CgiStatus (* TplCallback)(HttpdConnData *connData, char *token, void **arg);

void httpdRegisterFrogFs(frogfs_fs_t *fs);
CgiStatus cgiFrogFsHook(HttpdConnData *connData);
CgiStatus ICACHE_FLASH_ATTR cgiFrogFsTemplate(HttpdConnData *connData);

/**
 * @return 1 upon success, 0 upon failure
 */
int tplSend(HttpdConnData *conn, const char *str, int len);

#endif // CONFIG_ESPHTTPD_USE_FROGFS

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // HTTPDFROGFS_H
