#pragma once

#include "httpd.h"

CgiStatus cgiRedirect(HttpdConnData *connData);
CgiStatus cgiRedirectToHostname(HttpdConnData *connData);
CgiStatus cgiRedirectApClientToHostname(HttpdConnData *connData);
