#ifndef HTTPD_PLATFORM_H
#define HTTPD_PLATFORM_H

#include "libesphttpd/platform.h"

/**
 * @return number of bytes that were written
 */
int httpdPlatSendData(HttpdInstance *pInstance, ConnTypePtr conn, char *buff, int len);

void httpdPlatDisconnect(ConnTypePtr conn);
void httpdPlatDisableTimeout(ConnTypePtr conn);

void httpdPlatLock(HttpdInstance *pInstance);
void httpdPlatUnlock(HttpdInstance *pInstance);

HttpdPlatTimerHandle httpdPlatTimerCreate(const char *name, int periodMs, int autoreload, void (*callback)(void *arg), void *ctx);
void httpdPlatTimerStart(HttpdPlatTimerHandle timer);
void httpdPlatTimerStop(HttpdPlatTimerHandle timer);
void httpdPlatTimerDelete(HttpdPlatTimerHandle timer);


#endif
