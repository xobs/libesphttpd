/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
Platform-dependent routines, FreeRTOS version


Thanks to my collague at Espressif for writing the foundations of this code.
*/

/* Copyright 2017 Jeroen Domburg <git@j0h.nl> */
/* Copyright 2017 Chris Morgan <chmorgan@gmail.com> */

#if defined(linux) || defined(FREERTOS)

#ifdef linux
#include <libesphttpd/linux.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <unistd.h>

#else
#include <libesphttpd/esp.h>
#endif

#include "libesphttpd/httpd.h"
#include "libesphttpd/platform.h"
#include "httpd-platform.h"

#ifdef FREERTOS
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#ifdef ESP32
#include "lwip/sockets.h"
#else
#include "lwip/lwip/sockets.h"
#endif
#endif // #ifdef FREERTOS

static int httpPort;
static int httpMaxConnCt;
static struct sockaddr_in httpListenAddress;
static HttpdFlags httpdFlags;

#ifdef linux
static pthread_mutex_t httpdMux;
#else
static xQueueHandle httpdMux;
#endif

#ifdef CONFIG_ESPHTTPD_SSL_SUPPORT
#include <openssl/ssl.h>
#ifdef linux
#include <openssl/err.h>
#endif
SSL_CTX *ctx;
#endif


struct  RtosConnType{
	int fd;
	int needWriteDoneNotif;
	int needsClose;
	int port;
	char ip[4];
#ifdef CONFIG_ESPHTTPD_SSL_SUPPORT
	SSL *ssl;
#endif
};

static RtosConnType rconn[HTTPD_MAX_CONNECTIONS];

int ICACHE_FLASH_ATTR httpdPlatSendData(ConnTypePtr conn, char *buff, int len) {
	conn->needWriteDoneNotif=1;
#ifdef CONFIG_ESPHTTPD_SSL_SUPPORT
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

#ifdef linux
//Set/clear global httpd lock.
void ICACHE_FLASH_ATTR httpdPlatLock() {
	pthread_mutex_lock(&httpdMux);
}

void ICACHE_FLASH_ATTR httpdPlatUnlock() {
	pthread_mutex_unlock(&httpdMux);
}
#else
//Set/clear global httpd lock.
void ICACHE_FLASH_ATTR httpdPlatLock() {
	xSemaphoreTakeRecursive(httpdMux, portMAX_DELAY);
}

void ICACHE_FLASH_ATTR httpdPlatUnlock() {
	xSemaphoreGiveRecursive(httpdMux);
}
#endif

void closeConnection(RtosConnType *rconn)
{
	httpdDisconCb(rconn, rconn->ip, rconn->port);

#ifdef CONFIG_ESPHTTPD_SSL_SUPPORT
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

#ifdef CONFIG_ESPHTTPD_SSL_SUPPORT
	SSL_free(rconn->ssl);
	httpd_printf("SSL_free() complete\n");
	rconn->ssl = 0;
#endif
}

#ifdef CONFIG_ESPHTTPD_SSL_SUPPORT
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
#ifdef linux
		ERR_print_errors_fp(stderr);
#endif
		httpd_printf("SSL_CTX_use_certificate_ASN1 failed error %d\n", ret);
		goto failed2;
	}
	httpd_printf("OK\n");

	httpd_printf("SSL server context setting private key......\n");
	ret = SSL_CTX_use_RSAPrivateKey_ASN1(ctx, prvtkey_der_start, prvtkey_der_bytes);
	if (!ret) {
#ifdef linux
		ERR_print_errors_fp(stderr);
#endif
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
#ifdef linux
static void* platHttpServerTask(void *pvParameters) {
#else
static void platHttpServerTask(void *pvParameters) {
#endif
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

#ifdef linux
	pthread_mutex_init(&httpdMux, NULL);
#else
	httpdMux=xSemaphoreCreateRecursiveMutex();
#endif

	for (x=0; x<HTTPD_MAX_CONNECTIONS; x++) {
		rconn[x].fd=-1;
	}

	/* Construct local address structure */
	memset(&server_addr, 0, sizeof(server_addr)); /* Zero out structure */
	server_addr.sin_family = AF_INET;			/* Internet address family */
	server_addr.sin_addr.s_addr = httpListenAddress.sin_addr.s_addr;
#ifndef linux
	server_addr.sin_len = sizeof(server_addr);
#endif
	server_addr.sin_port = htons(httpPort); /* Local port */

#ifdef CONFIG_ESPHTTPD_SSL_SUPPORT
	ctx = sslCreateContext();
	if(!ctx)
	{
		httpd_printf("%s: failed to create ssl context\n", __FUNCTION__);
#ifdef linux
		return NULL;
#else
		vTaskDelete(NULL);
#endif
	}
#endif

	/* Create socket for incoming connections */
	do{
		listenfd = socket(AF_INET, SOCK_STREAM, 0);
		if (listenfd == -1) {
			httpd_printf("%s: failed to create sock!\n", __FUNCTION__);
			vTaskDelay(1000/portTICK_RATE_MS);
		}
	} while(listenfd == -1);

	/* Bind to the local port */
	do{
		ret = bind(listenfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		if (ret != 0) {
			httpd_printf("%s: failed to bind!\n", __FUNCTION__);
			perror("bind failure");
			vTaskDelay(1000/portTICK_RATE_MS);
		}
	} while(ret != 0);

	do{
		/* Listen to the local connection */
		ret = listen(listenfd, HTTPD_MAX_CONNECTIONS);
		if (ret != 0) {
			httpd_printf("%s: failed to listen!\n", __FUNCTION__);
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
		ret = select(maxfdp+1, &readset, &writeset, NULL, NULL);//&timeout
		printf("sel ret\n");
		if(ret > 0){
			//See if we need to accept a new connection
			if (FD_ISSET(listenfd, &readset)) {
				len=sizeof(struct sockaddr_in);
				remotefd = accept(listenfd, (struct sockaddr *)&remote_addr, (socklen_t *)&len);
				if (remotefd<0) {
					httpd_printf("%s: Huh? Accept failed.\n", __FUNCTION__);
					continue;
				}
				for(x=0; x<HTTPD_MAX_CONNECTIONS; x++) if (rconn[x].fd==-1) break;
				if (x==HTTPD_MAX_CONNECTIONS) {
					httpd_printf("%s: Huh? Got accept with all slots full.\n", __FUNCTION__);
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

#ifdef CONFIG_ESPHTTPD_SSL_SUPPORT
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
						httpd_printf("%s: memory exhausted!\n", __FUNCTION__);
						httpdDisconCb(&rconn[x], rconn[x].ip, rconn[x].port);
						closeConnection(&rconn[x]);
					}
#ifdef CONFIG_ESPHTTPD_SSL_SUPPORT
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
#ifdef linux
	return NULL;
#endif
}

#ifdef linux

#include <signal.h>
#include <time.h>

void platform_timer_handler (union sigval val)
{
	HttpdPlatTimerHandle handle = val.sival_ptr;

	// call the callback
	handle->callback(handle->callbackArg);

	// stop the timer if we aren't autoreloading
	if(!handle->autoReload)
	{
		httpdPlatTimerStop(handle);
	}
}

HttpdPlatTimerHandle httpdPlatTimerCreate(const char *name, int periodMs, int autoreload, void (*callback)(void *arg), void *ctx) {

	struct sigevent event;
	HttpdPlatTimerHandle handle = (HttpdPlatTimerHandle)malloc(sizeof(HttpdPlatTimer));

	handle->autoReload = autoreload;
	handle->callback = callback;
	handle->timerPeriodMS = periodMs;
	handle->callbackArg = ctx;

	event.sigev_notify = SIGEV_THREAD;
	event.sigev_notify_function = platform_timer_handler;
	event.sigev_value.sival_ptr = handle;

	int retval = timer_create(CLOCK_MONOTONIC, &event, &(handle->timer));
	if(retval != 0)
	{
		httpd_printf("timer_create() failed retval %d\n", retval);
	}

	return handle;
}

void httpdPlatTimerStart(HttpdPlatTimerHandle handle) {
	struct itimerspec new_value;
	struct itimerspec old_value;
	int seconds = handle->timerPeriodMS / 1000;
	int nsec = ((handle->timerPeriodMS % 1000) * 1000000);
	new_value.it_value.tv_sec = seconds;
	new_value.it_value.tv_nsec = nsec;
	new_value.it_interval.tv_sec = seconds;
	new_value.it_interval.tv_nsec = nsec;
	int retval = timer_settime(handle->timer, 0,
							&new_value,
							&old_value);

	if(retval != 0)
	{
		httpd_printf("timer start timer_settime() failed retval %d\n", retval);
	}
}

void httpdPlatTimerStop(HttpdPlatTimerHandle handle) {
	struct itimerspec new_value;
	struct itimerspec old_value;
	memset(&new_value, 0, sizeof(struct itimerspec));
	int retval = timer_settime(handle->timer, 0,
							&new_value,
							&old_value);

	if(retval != 0)
	{
		httpd_printf("timer start timer_settime() failed retval %d\n", retval);
	}
}

void httpdPlatTimerDelete(HttpdPlatTimerHandle handle) {
	timer_delete(handle->timer);
	free(handle);
}
#else
HttpdPlatTimerHandle httpdPlatTimerCreate(const char *name, int periodMs, int autoreload, void (*callback)(void *arg), void *ctx) {
	HttpdPlatTimerHandle ret;
#ifdef ESP32
	ret=xTimerCreate(name, pdMS_TO_TICKS(periodMs), autoreload?pdTRUE:pdFALSE, ctx, callback);
#else
	ret=xTimerCreate((const signed char * const)name, (periodMs / portTICK_RATE_MS), autoreload?pdTRUE:pdFALSE, ctx, callback);
#endif
	return ret;
}

void httpdPlatTimerStart(HttpdPlatTimerHandle timer) {
	xTimerStart(timer, 0);
}

void httpdPlatTimerStop(HttpdPlatTimerHandle timer) {
	xTimerStop(timer, 0);
}

void httpdPlatTimerDelete(HttpdPlatTimerHandle timer) {
	xTimerDelete(timer, 0);
}
#endif

//Initialize listening socket, do general initialization
HttpdInitStatus ICACHE_FLASH_ATTR httpdPlatInit(int port, int maxConnCt, uint32_t listenAddress, HttpdFlags flags) {
	HttpdInitStatus status = InitializationSuccess;
	httpPort=port;
	httpMaxConnCt=maxConnCt;
	httpListenAddress.sin_addr.s_addr = listenAddress;
	httpdFlags = flags;

	// check flags against feature support
#ifdef CONFIG_ESPHTTPD_SSL_SUPPORT
	if(!(flags & HTTPD_FLAG_SSL))
	{
		httpd_printf("ERROR: SSL flag not set but SSL support is enabled\n");
		status = FeatureFlagMismatch;
		return status;
	}
#else
	if(flags & HTTPD_FLAG_SSL)
	{
		httpd_printf("ERROR: SSL flag set but SSL support not enabled\n");
		status = FeatureFlagMismatch;
		return status;
	}
#endif

#ifdef linux
	pthread_t thread;
	pthread_create(&thread, NULL, platHttpServerTask, NULL);
#else
#ifdef ESP32
	xTaskCreate(platHttpServerTask, (const char *)"esphttpd", HTTPD_STACKSIZE, NULL, 4, NULL);
#else
	xTaskCreate(platHttpServerTask, (const signed char *)"esphttpd", HTTPD_STACKSIZE, NULL, 4, NULL);
#endif
#endif

	return status;
}

#endif
