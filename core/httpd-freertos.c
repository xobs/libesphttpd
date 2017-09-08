/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
ESP8266 web server - platform-dependent routines, FreeRTOS version


Thanks to my collague at Espressif for writing the foundations of this code.
*/

/* Copyright 2017 Jeroen Domburg <git@j0h.nl> */
/* Copyright 2017 Chris Morgan <chmorgan@gmail.com> */

#ifdef FREERTOS


#include <libesphttpd/esp8266.h>
#include "libesphttpd/httpd.h"
#include "libesphttpd/platform.h"
#include "httpd-platform.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#ifdef ESP32
#include "lwip/sockets.h"
#else
#include "lwip/lwip/sockets.h"
#endif

static int httpPort;
static int httpMaxConnCt;
static struct sockaddr_in httpListenAddress;
static xQueueHandle httpdMux;

#if CONFIG_ESPHTTPD_SSL_SUPPORT
#include "openssl/ssl.h"
SSL_CTX *ctx;
#endif


struct  RtosConnType{
	int fd;
	int needWriteDoneNotif;
	int needsClose;
	int port;
	char ip[4];
#if CONFIG_ESPHTTPD_SSL_SUPPORT
	SSL *ssl;
#endif
};

static RtosConnType rconn[HTTPD_MAX_CONNECTIONS];

int ICACHE_FLASH_ATTR httpdPlatSendData(ConnTypePtr conn, char *buff, int len) {
	conn->needWriteDoneNotif=1;
#if CONFIG_ESPHTTPD_SSL_SUPPORT
	return (SSL_write(conn->ssl, buff, len) >= 0);
#else
	return (write(conn->fd, buff, len)>=0);
#endif
}

void ICACHE_FLASH_ATTR httpdPlatDisconnect(ConnTypePtr conn) {
	conn->needsClose=1;
	conn->needWriteDoneNotif=1; //because the real close is done in the writable select code
}

void httpdPlatDisableTimeout(ConnTypePtr conn) {
	//Unimplemented for FreeRTOS
}

//Set/clear global httpd lock.
void ICACHE_FLASH_ATTR httpdPlatLock() {
	xSemaphoreTakeRecursive(httpdMux, portMAX_DELAY);
}

void ICACHE_FLASH_ATTR httpdPlatUnlock() {
	xSemaphoreGiveRecursive(httpdMux);
}

void closeConnection(RtosConnType *rconn)
{
	httpdDisconCb(rconn, rconn->ip, rconn->port);

#if CONFIG_ESPHTTPD_SSL_SUPPORT
	int retval;
	retval = SSL_shutdown(rconn->ssl);
	if(retval == 1)
	{
		httpd_printf("SSL_shutdown() success\n");
	} else if(retval == 0)
	{
		httpd_printf("SSL_shutdown() call again\n");
	} else
	{
		httpd_printf("SSL_shutdown() error %d\n", retval);
	}
	httpd_printf("SSL_shutdown() complete\n");
#endif

	close(rconn->fd);
	rconn->fd=-1;

#if CONFIG_ESPHTTPD_SSL_SUPPORT
	SSL_free(rconn->ssl);
	httpd_printf("SSL_free() complete\n");
	rconn->ssl = 0;
#endif
}

#if CONFIG_ESPHTTPD_SSL_SUPPORT
static SSL_CTX* sslCreateContext()
{
	int ret;
	SSL_CTX *ctx = NULL;

	extern const unsigned char cacert_der_start[] asm("_binary_cacert_der_start");
	extern const unsigned char cacert_der_end[]   asm("_binary_cacert_der_end");
	const unsigned int cacert_der_bytes = cacert_der_end - cacert_der_start;

	extern const unsigned char prvtkey_der_start[] asm("_binary_prvtkey_der_start");
	extern const unsigned char prvtkey_der_end[]   asm("_binary_prvtkey_der_end");
	const unsigned int prvtkey_der_bytes = prvtkey_der_end - prvtkey_der_start;

	httpd_printf("SSL server context create ......\n");

	ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		httpd_printf("SSL_CXT_new failed\n");
		goto failed1;
	}
	httpd_printf("OK\n");

	httpd_printf("SSL server context setting ca certificate......\n");
	ret = SSL_CTX_use_certificate_ASN1(ctx, cacert_der_bytes, cacert_der_start);
	if (!ret) {
		httpd_printf("SSL_CTX_use_certificate_ASN1 failed error %d\n", ret);
		goto failed2;
	}
	httpd_printf("OK\n");

	httpd_printf("SSL server context setting private key......\n");
	ret = SSL_CTX_use_RSAPrivateKey_ASN1(ctx, prvtkey_der_start, prvtkey_der_bytes);
	if (!ret) {
		httpd_printf("SSL_CTX_use_RSAPrivateKey_ASN1 failed error %d\n", ret);
		goto failed2;
	}
	httpd_printf("\n");

	return ctx;

failed2:
	httpd_printf("%s failed\n", __FUNCTION__);
	SSL_CTX_free(ctx);
	ctx = NULL;
failed1:
	return ctx;
}
#endif

#define RECV_BUF_SIZE 2048
static void platHttpServerTask(void *pvParameters) {
	int32 listenfd;
	int32 remotefd;
	int32 len;
	int32 ret;
	int x;
	int maxfdp = 0;
	char *precvbuf;
	fd_set readset,writeset;
	struct sockaddr name;
	//struct timeval timeout;
	struct sockaddr_in server_addr;
	struct sockaddr_in remote_addr;

	httpdMux=xSemaphoreCreateRecursiveMutex();

	for (x=0; x<HTTPD_MAX_CONNECTIONS; x++) {
		rconn[x].fd=-1;
	}

	/* Construct local address structure */
	memset(&server_addr, 0, sizeof(server_addr)); /* Zero out structure */
	server_addr.sin_family = AF_INET;			/* Internet address family */
	server_addr.sin_addr.s_addr = httpListenAddress.sin_addr.s_addr;
	server_addr.sin_len = sizeof(server_addr);
	server_addr.sin_port = htons(httpPort); /* Local port */

#if CONFIG_ESPHTTPD_SSL_SUPPORT
	ctx = sslCreateContext();
	if(!ctx)
	{
		httpd_printf("platHttpServerTask: failed to create ssl context\n");

		vTaskDelete(NULL);
	}
#endif

	/* Create socket for incoming connections */
	do{
		listenfd = socket(AF_INET, SOCK_STREAM, 0);
		if (listenfd == -1) {
			httpd_printf("platHttpServerTask: failed to create sock!\n");
			vTaskDelay(1000/portTICK_RATE_MS);
		}
	} while(listenfd == -1);

	/* Bind to the local port */
	do{
		ret = bind(listenfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		if (ret != 0) {
			httpd_printf("platHttpServerTask: failed to bind!\n");
			vTaskDelay(1000/portTICK_RATE_MS);
		}
	} while(ret != 0);

	do{
		/* Listen to the local connection */
		ret = listen(listenfd, HTTPD_MAX_CONNECTIONS);
		if (ret != 0) {
			httpd_printf("platHttpServerTask: failed to listen!\n");
			vTaskDelay(1000/portTICK_RATE_MS);
		}
	} while(ret != 0);

	httpd_printf("esphttpd: active and listening to connections.\n");
	while(1){
		// clear fdset, and set the select function wait time
		int socketsFull=1;
		maxfdp = 0;
		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		//timeout.tv_sec = 2;
		//timeout.tv_usec = 0;

		for(x=0; x<HTTPD_MAX_CONNECTIONS; x++){
			if (rconn[x].fd!=-1) {
				FD_SET(rconn[x].fd, &readset);
				if (rconn[x].needWriteDoneNotif) FD_SET(rconn[x].fd, &writeset);
				if (rconn[x].fd>maxfdp) maxfdp=rconn[x].fd;
				printf("Sel add %d (write %d)\n", (int)rconn[x].fd, rconn[x].needWriteDoneNotif);
			} else {
				socketsFull=0;
			}
		}

		if (!socketsFull) {
			FD_SET(listenfd, &readset);
			if (listenfd>maxfdp) maxfdp=listenfd;
			printf("Sel add listen %d\n", listenfd);
		}

		//polling all exist client handle,wait until readable/writable
		ret = lwip_select(maxfdp+1, &readset, &writeset, NULL, NULL);//&timeout
		printf("sel ret\n");
		if(ret > 0){
			//See if we need to accept a new connection
			if (FD_ISSET(listenfd, &readset)) {
				len=sizeof(struct sockaddr_in);
				remotefd = accept(listenfd, (struct sockaddr *)&remote_addr, (socklen_t *)&len);
				if (remotefd<0) {
					httpd_printf("platHttpServerTask: Huh? Accept failed.\n");
					continue;
				}
				for(x=0; x<HTTPD_MAX_CONNECTIONS; x++) if (rconn[x].fd==-1) break;
				if (x==HTTPD_MAX_CONNECTIONS) {
					httpd_printf("platHttpServerTask: Huh? Got accept with all slots full.\n");
					continue;
				}

				int keepAlive = 1; //enable keepalive
				int keepIdle = 60; //60s
				int keepInterval = 5; //5s
				int keepCount = 3; //retry times

				setsockopt(remotefd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
				setsockopt(remotefd, IPPROTO_TCP, TCP_KEEPIDLE, (void*)&keepIdle, sizeof(keepIdle));
				setsockopt(remotefd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
				setsockopt(remotefd, IPPROTO_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));

				rconn[x].fd=remotefd;
				rconn[x].needWriteDoneNotif=0;
				rconn[x].needsClose=0;

#if CONFIG_ESPHTTPD_SSL_SUPPORT
				httpd_printf("SSL server create ......\n");
				rconn[x].ssl = SSL_new(ctx);
				if (!rconn[x].ssl) {
					httpd_printf("SSL_new failed\n");
					//TODO: error handler here
				}
				httpd_printf("OK\n");

				SSL_set_fd(rconn[x].ssl, rconn[x].fd);

				httpd_printf("SSL server accept client ......\n");
				ret = SSL_accept(rconn[x].ssl);
				if (!ret) {
					httpd_printf("SSL_accept failed\n");
					//TODO: error handler here
				}
				httpd_printf("OK\n");
#endif

				len=sizeof(name);
				getpeername(remotefd, &name, (socklen_t *)&len);
				struct sockaddr_in *piname=(struct sockaddr_in *)&name;

				rconn[x].port=piname->sin_port;
				memcpy(&rconn[x].ip, &piname->sin_addr.s_addr, sizeof(rconn[x].ip));

				httpdConnectCb(&rconn[x], rconn[x].ip, rconn[x].port);
				//os_timer_disarm(&connData[x].conn->stop_watch);
				//os_timer_setfn(&connData[x].conn->stop_watch, (os_timer_func_t *)httpserver_conn_watcher, connData[x].conn);
				//os_timer_arm(&connData[x].conn->stop_watch, STOP_TIMER, 0);
//				httpd_printf("httpserver acpt index %d sockfd %d!\n", x, remotefd);
			}

			//See if anything happened on the existing connections.
			for(x=0; x < HTTPD_MAX_CONNECTIONS; x++){
				//Skip empty slots
				if (rconn[x].fd==-1) continue;

				//Check for write availability first: the read routines may write needWriteDoneNotif while
				//the select didn't check for that.
				if (rconn[x].needWriteDoneNotif && FD_ISSET(rconn[x].fd, &writeset)) {
					rconn[x].needWriteDoneNotif=0; //Do this first, httpdSentCb may write something making this 1 again.
					if (rconn[x].needsClose) {
						//Do callback and close fd.
						closeConnection(&rconn[x]);
					} else {
						httpdSentCb(&rconn[x], rconn[x].ip, rconn[x].port);
					}
				}

				if (FD_ISSET(rconn[x].fd, &readset)) {
					precvbuf=(char*)malloc(RECV_BUF_SIZE);
					if (precvbuf==NULL) {
						httpd_printf("platHttpServerTask: memory exhausted!\n");
						httpdDisconCb(&rconn[x], rconn[x].ip, rconn[x].port);
						closeConnection(&rconn[x]);
					}
#if CONFIG_ESPHTTPD_SSL_SUPPORT
					ret = SSL_read(rconn[x].ssl, precvbuf, RECV_BUF_SIZE - 1);
#else
					ret = recv(rconn[x].fd, precvbuf, RECV_BUF_SIZE,0);
#endif
					if (ret > 0) {
						//Data received. Pass to httpd.
						httpdRecvCb(&rconn[x], rconn[x].ip, rconn[x].port, precvbuf, ret);
					} else {
						//recv error,connection close
						closeConnection(&rconn[x]);
					}
					if (precvbuf) free(precvbuf);
				}
			}
		}
	}

#if 0
//Deinit code, not used here.
	/*release data connection*/
	for(x=0; x < HTTPD_MAX_CONNECTIONS; x++){
		//find all valid handle
		if(connData[x].conn == NULL) continue;
		if(connData[x].conn->sockfd >= 0){
			os_timer_disarm((os_timer_t *)&connData[x].conn->stop_watch);
			close(connData[x].conn->sockfd);
			connData[x].conn->sockfd = -1;
			connData[x].conn = NULL;
			if(connData[x].cgi!=NULL) connData[x].cgi(&connData[x]); //flush cgi data
			httpdRetireConn(&connData[x]);
		}
	}
	/*release listen socket*/
	close(listenfd);

	vTaskDelete(NULL);
#endif
}


HttpdPlatTimerHandle httpdPlatTimerCreate(const char *name, int periodMs, int autoreload, void (*callback)(void *arg), void *ctx) {
	TimerHandle_t ret;
	ret=xTimerCreate(name, pdMS_TO_TICKS(periodMs), autoreload?pdTRUE:pdFALSE, ctx, callback);
	return (HttpdPlatTimerHandle)ret;
}

void httpdPlatTimerStart(HttpdPlatTimerHandle timer) {
	xTimerStart((TimerHandle_t)timer, 0);
}

void httpdPlatTimerStop(HttpdPlatTimerHandle timer) {
	xTimerStop((TimerHandle_t)timer, 0);
}

void httpdPlatTimerDelete(HttpdPlatTimerHandle timer) {
	xTimerDelete((TimerHandle_t)timer, 0);
}


//Initialize listening socket, do general initialization
void ICACHE_FLASH_ATTR httpdPlatInit(int port, int maxConnCt, uint32_t listenAddress) {
	httpPort=port;
	httpMaxConnCt=maxConnCt;
	httpListenAddress.sin_addr.s_addr = listenAddress;
#ifdef ESP32
	xTaskCreate(platHttpServerTask, (const char *)"esphttpd", HTTPD_STACKSIZE, NULL, 4, NULL);
#else
	xTaskCreate(platHttpServerTask, (const signed char *)"esphttpd", HTTPD_STACKSIZE, NULL, 4, NULL);
#endif
}

#endif
