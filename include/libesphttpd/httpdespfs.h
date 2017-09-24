#ifndef HTTPDESPFS_H
#define HTTPDESPFS_H

#include "httpd.h"

CgiStatus cgiEspFsHook(HttpdConnData *connData);
CgiStatus ICACHE_FLASH_ATTR cgiEspFsTemplate(HttpdConnData *connData);

#endif
