/* anet.c -- Basic TCP socket stuff made a bit less boring
 *
 */

#ifndef __AE_NET_H
#define __AE_NET_H

#include <sys/types.h>

#define AE_NET_OK 0
#define AE_NET_ERR -1
#define AE_NET_ERR_LEN 256

/* Flags used with certain functions. */
#define AE_NET_NONE 0
#define AE_NET_IP_ONLY (1<<0)

int ae_net_tcp_connect(char * err, char * addr, int port);
int ae_net_tcp_non_block_connect(char * err, char * addr, int port);
int ae_net_tcp_non_block_bind_connect(char * err, char * addr, int port, char * source_addr);
int ae_net_tcp_non_block_best_effort_bind_connect(char * err, char * addr, int port, char * source_addr);
int ae_net_unix_connect(char * err, char * path);
int ae_net_unix_non_block_connect(char * err, char *path);
int ae_net_read(int fd, char *buf, int count);
int ae_net_resolve(char *err, char *host, char *ipbuf, size_t ipbuf_len);
int ae_net_resolve_ip(char *err, char *host, char *ipbuf, size_t ipbuf_len);
int ae_net_tcp_server(char *err, int port, char *bindaddr, int backlog);
int ae_net_unix_server(char *err, char *path, mode_t perm, int backlog);
int ae_net_tcp_accept(char *err, int serversock, char *ip, size_t ip_len, int *port);
int ae_net_unix_accept(char *err, int serversock);
int ae_net_write(int fd, char *buf, int count);

int ae_net_non_block(char * err, int fd);
int ae_net_block(char * err, int fd);

int ae_net_enable_tcp_no_delay(char *err, int fd);
int ae_net_disable_tcp_no_delay(char *err, int fd);
int ae_net_tcp_keep_alive(char *err, int fd);
int ae_net_send_timeout(char *err, int fd, long long ms);
int ae_net_peer_to_string(int fd, char *ip, size_t ip_len, int *port);
int ae_net_keep_alive(char *err, int fd, int interval);
int ae_net_sock_name(int fd, char *ip, size_t ip_len, int *port);
int ae_net_format_addr(char *fmt, size_t fmt_len, char *ip, int port);
int ae_net_format_peer(int fd, char *fmt, size_t fmt_len);
int ae_net_format_sock(int fd, char *fmt, size_t fmt_len);

#endif
