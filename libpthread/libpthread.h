/*
 Authors: ZhangXuelian
 	


 Changes:
 	
	
*/
#ifndef _TCP_LIB_PTHREAD_H_
#define _TCP_LIB_PTHREAD_H_
#ifdef __cplusplus
extern "C"{
#endif


#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <netdb.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/times.h>
#include <sys/timex.h>	//	for ntpc
#include <sys/mman.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/vfs.h>
#include <dirent.h>
#include <signal.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <net/if_arp.h>
#include <sys/soundcard.h>

#include <linux/tcp.h>
#include "tcp_lib_types.h"

#define MIN_PRIORITY 0
#define MAX_PRIORITY 5

typedef struct tagThreadContext
{
	unsigned long alive_threshold;
	int priority;
	unsigned long tick;
	bool exit;
	bool quited;
	pthread_t thread;
	void * (* handler)(void * arg);
} THREAD_CONTEXT;
bool create_thread(THREAD_CONTEXT * c);
#define end_thread(c) c.exit = true
bool is_thread_alive(THREAD_CONTEXT * c);
#define is_thread_quited(c) c.quited
void set_thread_priority(int priority);

#ifdef __cplusplus
}
#endif
#endif

