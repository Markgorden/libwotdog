/*
 All source file must include this head file
 
 Authors: ZhangXuelian

 Changes:
 	
 */

#ifndef __SERVER_H__
#define __SERVER_H__

#define MY_VERSION "1.0.0.1"

#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <limits.h>
#include <float.h>
#include <math.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <locale.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include "../libaenet/ae.h" 
#include "../libaenet/net.h"
#include "../libstl/libstl.h"
#include "../libutility/libutility.h"
#include "../liblog/liblog.h"
#include "../libcrypt/libcrypt.h"
#include "../libuuid/libc_uuid/get_uuid.h"
#include "../libpthread/libpthread.h"
#include "../libprotocol/protocol.h"
// for lua
#include "lua/lua.h"
#include "lua/luaconf.h"
#include "lua/lauxlib.h"
#include "lua/lualib.h"

// Error codes 
#define C_OK                    0
#define C_ERR                   -1

#define CONFIG_MIN_RESERVED_FDS 32
#define CONFIG_FDSET_INCR (CONFIG_MIN_RESERVED_FDS+96)
#define NET_IP_STR_LEN 46 
#define PROTO_REPLY_CHUNK_BYTES (16*1024) // 16k output buffer 
#define CONFIG_BINDADDR_MAX 16

#define LRU_BITS 24
#define LRU_CLOCK_MAX ((1<<LRU_BITS)-1) 
#define LRU_CLOCK_RESOLUTION 1000 

#define CLIENT_DEVICE (1<<0)  
#define CLIENT_MASTER (1<<1)  
#define CLIENT_TRANSVERTER (1<<2) 
#define CLIENT_OTHER_SERVER (1<<3)
#define CLIENT_PUBSUB (1<<4)  
#define CLIENT_OTHER (1<<5)  
#define CLIENT_CLOSE_AFTER_REPLY (1<<6)
#define CLIENT_UNIX_SOCKET (1<<11) 

#define PROTO_IOBUF_LEN         (1024*16)  // Generic I/O buffer size 
#define CONFIG_DEFAULT_PID_FILE "/var/run/server_fw.pid"
#define NET_MAX_WRITES_PER_EVENT (1024*64)
#define NET_PEER_ID_LEN (NET_IP_STR_LEN+32) // Must be enough for ip:port

typedef long long mstime_t; /* millisecond time type. */

#include "../libprotocol/protocol.h"

// client protocol handler
typedef struct __tag_client_handler
{
	int client_type;
	void (* write)(void * client);
	void (* read)(void * client);
	void (* connect)(void * client);
	void (* re_connect)(void * client);
	void (* disconnect)(void * client);
	void (* check_timeout)(void * client);
	bool (* parse_recved_data)(void * client);
	void * sub_client_handler; // 用于不同类型的client handler的私有业务解析。
} CLIENT_HANDLER;

typedef struct __tag_client_handler_list
{
	int magic;   // client magic
	int client_type; // client name
	CLIENT_HANDLER * client_handler;
}CLIENT_HANDLER_LIST;

typedef struct __tag_client {
    uint64_t id;            
    sds peerid;             
	int fd;

	sds querybuf;           
	size_t client_max_querybuf_len; 
	size_t querybuf_peak;   

    int reqtype;
	int flags;

    time_t ctime;           
    time_t lastinteraction; 

    int authenticated;     

	int bufpos;
	char buf[PROTO_REPLY_CHUNK_BYTES];
	list *reply;            
	unsigned long long reply_bytes;
	size_t sentlen;

	CLIENT_HANDLER * client_handler; // 创建Client实例时，给它赋值
} CLIENT;


typedef struct __tag_Server_Context 
{
    struct {
		pid_t pid; 
		char * configfile; 
		int activerehashing;
		int arch_bits; 
		time_t stat_starttime; 
		// for server_cron
		int hz; 
		int cronloops;
		char *pidfile;
		list * client_handler;
	} common;

    struct {
		AE_EVENT_LOOP * el;
		int fd;
		int port; 
		int tcp_backlog; 
		char * bindaddr[CONFIG_BINDADDR_MAX]; 
		int bindaddr_count; 

		int ipfd[CONFIG_BINDADDR_MAX]; 
		int ipfd_count; 
		int sofd; 
		int cfd_count; 

		dict * clients;      // the key is device_info
		dict * clients_temp; // the key is fd.
		list * clients_to_close; 
		list * clients_pending_write;
		CLIENT * current_client; 
		int clients_paused; 
		char neterr[AE_NET_ERR_LEN];
		dict * migrate_cached_sockets;
		//uint64_t next_client_id; 
		int protected_mode; 
		long long stat_numconnections;
		long long stat_rejected_conn; 
	} net;
	
	#define NUM_OPTIONS 20
	char * config_ex[NUM_OPTIONS];    // server configuration parameters
	struct {
		int maxidletime;              
		int tcpkeepalive;             
		size_t client_max_querybuf_len;
		int supervised;                
		int supervised_mode;           
		int daemonize;                 
	} config;
	
    struct {
		int state;  
		char * logfile;
		int verbosity;  
        int syslog_enabled;
        int bug_report_start; 
		long long stat_net_input_bytes; 
		long long stat_net_output_bytes;
	}log;
	
    unsigned int maxclients;     
    unsigned long long maxmemory;
    int maxmemory_policy;        
    int maxmemory_samples;       

    time_t unixtime;        
    long long mstime;       
    unsigned lruclock:LRU_BITS; 

	struct {
		//lua_State *lua; 
		//dict * lua_scripts;
	}lua;
}SERVER_CONTENT;

extern SERVER_CONTENT g_server_content;

// t_dict.c
void * get_element(dict * d, char * key);
int delete_element(dict * d, char *key);
int set_element(dict * d, void * key, void * val);
void update_element(dict * d, void * key, void * value);
int do_element_exist(dict * d, void * key);
dictEntry * get_random_element(dict * db);

// server_scron.c
int server_cron(struct AE_EVENT_LOOP * event_loop, long long id, void * client_data);
void clients_cron(void);
void update_cached_time(void);

// networking.c
CLIENT * create_client(int fd);
void free_client_async(CLIENT *c);
void free_client(CLIENT *c);
void send_reply_to_client(AE_EVENT_LOOP * el, int fd, void * privdata, int mask);

// option.c
#define MAX_OPTIONS 40
extern const char *config_options[];
void process_command_line_arguments(char *argv[], char **options);
void get_config(char ** config, const char **options) ;

#endif


