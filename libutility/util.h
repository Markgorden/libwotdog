/*
 */

#ifndef __UTILITY_UTIL_H
#define __UTILITY_UTIL_H

#include "../include/tcp_lib_types.h"
#include "sds.h"
#include <stdint.h>
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

void os_thread_sleep(unsigned int tm);
void trim(char ** s);
bool str2mac(const char * str, unsigned char * mac);
#define mac2str(mac, str) sprintf(str,"%02X%02X%02X%02X%02X%02X", (unsigned char)mac[0], (unsigned char)mac[1], (unsigned char)mac[2], (unsigned char)mac[3], (unsigned char)mac[4], (unsigned char)mac[5])
void print_buf(char *buf, int len);
unsigned int base64_encode(const unsigned char * src, unsigned int src_len, char * dest);
unsigned int base64_decode(const char * src, unsigned int src_len, unsigned char * dest);

typedef struct 
{
	unsigned long S[4][256],P[18];
} blf_ctx;

void Blowfish_encipher(blf_ctx *c,unsigned long *xl,unsigned long *xr);
void Blowfish_decipher(blf_ctx *c,unsigned long * xl, unsigned long *xr);
void InitBlowfish (blf_ctx *c,unsigned char* key,unsigned int key_len);

#define MSG_MAGIC		0xaaffaaee
typedef struct tagMsg
{
	unsigned int magic;
	unsigned int msg;
	unsigned int param1;
	unsigned int param2;
	unsigned int param3;
	unsigned int param4;
} MSG;

typedef struct tagMsgConext
{
	int s_w;
	int s_r;
	pthread_mutex_t mutex;
	char buffer[sizeof(MSG)];
	unsigned int len;
} MSG_CONTEXT;

bool create_msg_queue(MSG_CONTEXT * c, unsigned int size);
void destroy_msg_queue(MSG_CONTEXT * c);
bool post_msg(MSG_CONTEXT * c, MSG * msg);
bool send_msg(MSG_CONTEXT * c, MSG * msg);
bool recv_msg(MSG_CONTEXT * c, MSG * msg);

//-------------------

int stringmatchlen(const char *p, int plen, const char *s, int slen, int nocase);
int stringmatch(const char *p, const char *s, int nocase);
long long memtoll(const char *p, int *err);
uint32_t digits10(uint64_t v);
uint32_t sdigits10(int64_t v);
int ll2string(char *s, size_t len, long long value);
int string2ll(const char *s, size_t slen, long long *value);
int string2l(const char *s, size_t slen, long *value);
int d2string(char *buf, size_t len, double value);
sds getAbsolutePath(char *filename);
int pathIsBaseName(char *path);

#ifdef MY_TEST
int utilTest(int argc, char **argv);
#endif

#endif
