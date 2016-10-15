/* anet.c -- Basic TCP socket stuff made a bit less boring
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#include "net.h"

static void ae_net_set_error(char *err, const char *fmt, ...)
{
    va_list ap;
    if (!err) return;
    va_start(ap, fmt);
    vsnprintf(err, AE_NET_ERR_LEN, fmt, ap);
    va_end(ap);
}

static inline int ae_net_set_block(char *err, int fd, int non_block) 
{
    int flags;
    if ((flags = fcntl(fd, F_GETFL)) == -1) {
        ae_net_set_error(err, "fcntl(F_GETFL): %s", strerror(errno));
        return AE_NET_ERR;
    }

    if (non_block)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) == -1) {
        ae_net_set_error(err, "fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
        return AE_NET_ERR;
    }
    return AE_NET_OK;
}

int ae_net_non_block(char *err, int fd) 
{
    return ae_net_set_block(err,fd,1);
}

int ae_net_block(char *err, int fd) 
{
    return ae_net_set_block(err,fd,0);
}

int ae_net_keep_alive(char *err, int fd, int interval)
{
    int val = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) == -1)
    {
        ae_net_set_error(err, "setsockopt SO_KEEPALIVE: %s", strerror(errno));
        return AE_NET_ERR;
    }

#ifdef __linux__
    /* Default settings are more or less garbage, with the keepalive time
     * set to 7200 by default on Linux. Modify settings to make the feature
     * actually useful. */

    /* Send first probe after interval. */
    val = interval;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0) {
        ae_net_set_error(err, "setsockopt TCP_KEEPIDLE: %s\n", strerror(errno));
        return AE_NET_ERR;
    }

    /* Send next probes after the specified interval. Note that we set the
     * delay as interval / 3, as we send three probes before detecting
     * an error (see the next setsockopt call). */
    val = interval/3;
    if (val == 0) val = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0) {
        ae_net_set_error(err, "setsockopt TCP_KEEPINTVL: %s\n", strerror(errno));
        return AE_NET_ERR;
    }
    val = 3;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0) {
        ae_net_set_error(err, "setsockopt TCP_KEEPCNT: %s\n", strerror(errno));
        return AE_NET_ERR;
    }
#else
    ((void) interval); /* Avoid unused var warning for non Linux systems. */
#endif

    return AE_NET_OK;
}

static int ae_net_set_tcp_no_delay(char * err, int fd, int val)
{
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) == -1)
    {
        ae_net_set_error(err, "setsockopt TCP_NODELAY: %s", strerror(errno));
        return AE_NET_ERR;
    }
    return AE_NET_OK;
}

int ae_net_enable_tcp_no_delay(char *err, int fd)
{
    return ae_net_set_tcp_no_delay(err, fd, 1);
}

int ae_net_disable_tcp_no_delay(char *err, int fd)
{
    return ae_net_set_tcp_no_delay(err, fd, 0);
}


int ae_net_set_send_buffer(char * err, int fd, int buffsize)
{
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffsize, sizeof(buffsize)) == -1)
    {
        ae_net_set_error(err, "setsockopt SO_SNDBUF: %s", strerror(errno));
        return AE_NET_ERR;
    }
    return AE_NET_OK;
}

int ae_net_tcp_keep_alive(char *err, int fd)
{
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) == -1)
	{
        ae_net_set_error(err, "setsockopt SO_KEEPALIVE: %s", strerror(errno));
        return AE_NET_ERR;
    }
    return AE_NET_OK;
}

int ae_net_send_timeout(char *err, int fd, long long ms)
{
    struct timeval tv;

    tv.tv_sec = ms/1000;
    tv.tv_usec = (ms%1000)*1000;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
        ae_net_set_error(err, "setsockopt SO_SNDTIMEO: %s", strerror(errno));
        return AE_NET_ERR;
    }
    return AE_NET_OK;
}

int ae_net_generic_resolve(char *err, char *host, char *ipbuf, size_t ipbuf_len,
                       int flags)
{
    struct addrinfo hints, *info;
    int rv;
    memset(&hints,0,sizeof(hints));
    if (flags & AE_NET_IP_ONLY) hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;  /* specify socktype to avoid dups */

    if ((rv = getaddrinfo(host, NULL, &hints, &info)) != 0) {
        ae_net_set_error(err, "%s", gai_strerror(rv));
        return AE_NET_ERR;
    }
    if (info->ai_family == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)info->ai_addr;
        inet_ntop(AF_INET, &(sa->sin_addr), ipbuf, ipbuf_len);
    } 
    freeaddrinfo(info);
    return AE_NET_OK;
}

int ae_net_resolve(char *err, char *host, char *ipbuf, size_t ipbuf_len) {
    return ae_net_generic_resolve(err,host,ipbuf,ipbuf_len,AE_NET_IP_ONLY);
}

int ae_net_resolve_ip(char *err, char *host, char *ipbuf, size_t ipbuf_len) {
    return ae_net_generic_resolve(err,host,ipbuf,ipbuf_len,AE_NET_IP_ONLY);
}

static int net_set_reuse_addr(char *err, int fd) 
{
    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) 
	{
        ae_net_set_error(err, "setsockopt SO_REUSEADDR: %s", strerror(errno));
        return AE_NET_ERR;
    }
    return AE_NET_OK;
}

static int net_create_socket(char *err, int domain) 
{
    int s;
    if ((s = socket(domain, SOCK_STREAM, 0)) == -1) 
	{
        ae_net_set_error(err, "creating socket: %s", strerror(errno));
        return AE_NET_ERR;
    }
	if (net_set_reuse_addr(err,s) == AE_NET_ERR) 
	{
		close(s);
		return AE_NET_ERR;
	}
	return s;
}

#define NET_CONNECT_NONE 0
#define NET_CONNECT_NONBLOCK 1
#define NET_CONNECT_BE_BINDING 2 /* Best effort binding. */
static int net_tcp_generic_connect(char *err, char *addr, int port,char *source_addr, int flags)
{
    int s = AE_NET_ERR, rv;
    char portstr[6];  /* strlen("65535") + 1; */
    struct addrinfo hints, *servinfo, *bservinfo, *p, *b;

    snprintf(portstr,sizeof(portstr),"%d",port);
    memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(addr,portstr,&hints,&servinfo)) != 0) 
	{
        ae_net_set_error(err, "%s", gai_strerror(rv));
        return AE_NET_ERR;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) 
	{
        if ((s = socket(p->ai_family,p->ai_socktype,p->ai_protocol)) == -1)
            continue;
        if (net_set_reuse_addr(err,s) == AE_NET_ERR) goto error;
        if (flags & NET_CONNECT_NONBLOCK && ae_net_non_block(err,s) != AE_NET_OK)
            goto error;
        if (source_addr) {
            int bound = 0;
            if ((rv = getaddrinfo(source_addr, NULL, &hints, &bservinfo)) != 0)
            {
                ae_net_set_error(err, "%s", gai_strerror(rv));
                goto error;
            }
            for (b = bservinfo; b != NULL; b = b->ai_next) 
			{
                if (bind(s,b->ai_addr,b->ai_addrlen) != -1) 
				{
                    bound = 1;
                    break;
                }
            }
            freeaddrinfo(bservinfo);
            if (!bound) 
			{
                ae_net_set_error(err, "bind: %s", strerror(errno));
                goto error;
            }
        }
        if (connect(s,p->ai_addr,p->ai_addrlen) == -1) 
		{
            if (errno == EINPROGRESS && flags & NET_CONNECT_NONBLOCK)
                goto end;
            close(s);
            s = AE_NET_ERR;
            continue;
        }
        goto end;
    }
    if (p == NULL)
        ae_net_set_error(err, "creating socket: %s", strerror(errno));

error:
    if (s != AE_NET_ERR) 
	{
        close(s);
        s = AE_NET_ERR;
    }

end:
    freeaddrinfo(servinfo);
    if (s == AE_NET_ERR && source_addr && (flags & NET_CONNECT_BE_BINDING))
	{
        return net_tcp_generic_connect(err,addr,port,NULL,flags);
    } 
	else 
	{
        return s;
    }
}

int ae_net_tcp_connect(char *err, char *addr, int port)
{
    return net_tcp_generic_connect(err,addr,port,NULL,NET_CONNECT_NONE);
}

int ae_net_tcp_non_block_connect(char *err, char *addr, int port)
{
    return net_tcp_generic_connect(err,addr,port,NULL,NET_CONNECT_NONBLOCK);
}

int ae_net_tcp_non_block_bind_connect(char *err, char *addr, int port, char *source_addr)
{
    return net_tcp_generic_connect(err,addr,port,source_addr,NET_CONNECT_NONBLOCK);
}

int ae_net_tcp_non_block_best_effort_bind_connect(char *err, char *addr, int port, char *source_addr)
{
    return net_tcp_generic_connect(err,addr,port,source_addr, NET_CONNECT_NONBLOCK|NET_CONNECT_BE_BINDING);
}

int ae_net_unix_generic_connect(char *err, char *path, int flags)
{
    int s;
    struct sockaddr_un sa;
    if ((s = net_create_socket(err,AF_LOCAL)) == AE_NET_ERR)
        return AE_NET_ERR;
    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path,path,sizeof(sa.sun_path)-1);
    if (flags & NET_CONNECT_NONBLOCK) {
        if (ae_net_non_block(err,s) != AE_NET_OK)
            return AE_NET_ERR;
    }
    if (connect(s,(struct sockaddr*)&sa,sizeof(sa)) == -1) 
	{
        if (errno == EINPROGRESS && 
			flags & NET_CONNECT_NONBLOCK)
            return s;
        ae_net_set_error(err, "connect: %s", strerror(errno));
        close(s);
        return AE_NET_ERR;
    }
    return s;
}

int ae_net_uxnix_connect(char *err, char *path)
{
    return ae_net_unix_generic_connect(err,path,NET_CONNECT_NONE);
}

int ae_net_unix_non_block_connect(char *err, char *path)
{
    return ae_net_unix_generic_connect(err,path,NET_CONNECT_NONBLOCK);
}

int ae_net_read(int fd, char *buf, int count)
{
    ssize_t nread, totlen = 0;
    while(totlen != count) {
        nread = read(fd,buf,count-totlen);
        if (nread == 0) return totlen;
        if (nread == -1) return -1;
        totlen += nread;
        buf += nread;
    }
    return totlen;
}

int ae_net_write(int fd, char *buf, int count)
{
    ssize_t nwritten, totlen = 0;
    while(totlen != count) {
        nwritten = write(fd,buf,count-totlen);
        if (nwritten == 0) return totlen;
        if (nwritten == -1) return -1;
        totlen += nwritten;
        buf += nwritten;
    }
    return totlen;
}

static int net_listen(char *err, int s, struct sockaddr *sa, socklen_t len, int backlog) 
{
    if (bind(s,sa,len) == -1) 
	{
        ae_net_set_error(err, "bind: %s", strerror(errno));
        close(s);
        return AE_NET_ERR;
    }
    if (listen(s, backlog) == -1) 
	{
        ae_net_set_error(err, "listen: %s", strerror(errno));
        close(s);
        return AE_NET_ERR;
    }
    return AE_NET_OK;
}

static int _net_tcp_server(char *err, int port, char *bindaddr, int af, int backlog)
{
    int s, rv;
    char _port[6];  /* strlen("65535") */
    struct addrinfo hints, *servinfo, *p;
    snprintf(_port,6,"%d",port);
    memset(&hints,0,sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;    
    if ((rv = getaddrinfo(bindaddr,_port,&hints,&servinfo)) != 0)
	{
        ae_net_set_error(err, "%s", gai_strerror(rv));
        return AE_NET_ERR;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((s = socket(p->ai_family,p->ai_socktype,p->ai_protocol)) == -1)
            continue;
        if (net_set_reuse_addr(err,s) == AE_NET_ERR) goto error;
        if (net_listen(err,s,p->ai_addr,p->ai_addrlen,backlog) == AE_NET_ERR) goto error;
        goto end;
    }
    if (p == NULL) 
	{
        ae_net_set_error(err, "unable to bind socket");
        goto error;
    }

error:
    s = AE_NET_ERR;
end:
    freeaddrinfo(servinfo);
    return s;
}

int ae_net_tcp_server(char *err, int port, char *bindaddr, int backlog)
{
    return _net_tcp_server(err, port, bindaddr, AF_INET, backlog);
}

int ae_net_unix_server(char *err, char *path, mode_t perm, int backlog)
{
    int s;
    struct sockaddr_un sa;

    if ((s = net_create_socket(err,AF_LOCAL)) == AE_NET_ERR)
        return AE_NET_ERR;
    memset(&sa,0,sizeof(sa));
    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path,path,sizeof(sa.sun_path)-1);
    if (net_listen(err,s,(struct sockaddr*)&sa,sizeof(sa),backlog) == AE_NET_ERR)
        return AE_NET_ERR;
    if (perm)
        chmod(sa.sun_path, perm);
    return s;
}

static int net_generic_accept(char *err, int s, struct sockaddr *sa, socklen_t *len)
{
    int fd;
    while(1) 
	{
        fd = accept(s,sa,len);
        if (fd == -1) 
		{
            if (errno == EINTR)
                continue;
            else {
                ae_net_set_error(err, "accept: %s", strerror(errno));
                return AE_NET_ERR;
            }
        }
        break;
    }
    return fd;
}

int ae_net_tcp_accept(char *err, int s, char *ip, size_t ip_len, int *port) 
{
    int fd;
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    if ((fd = net_generic_accept(err,s,(struct sockaddr*)&sa,&salen)) == -1)
        return AE_NET_ERR;
    if (sa.ss_family == AF_INET) 
	{
        struct sockaddr_in *s = (struct sockaddr_in *)&sa;
        if (ip) inet_ntop(AF_INET,(void*)&(s->sin_addr),ip,ip_len);
        if (port) *port = ntohs(s->sin_port);
    } 
    return fd;
}

int ae_net_unix_accept(char *err, int s) 
{
    int fd;
    struct sockaddr_un sa;
    socklen_t salen = sizeof(sa);
    if ((fd = net_generic_accept(err,s,(struct sockaddr*)&sa,&salen)) == -1)
        return AE_NET_ERR;
    return fd;
}

int ae_net_peer_to_string(int fd, char *ip, size_t ip_len, int *port) 
{
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);

    if (getpeername(fd,(struct sockaddr*)&sa,&salen) == -1) goto error;
    if (ip_len == 0) goto error;

    if (sa.ss_family == AF_INET) 
	{
        struct sockaddr_in *s = (struct sockaddr_in *)&sa;
        if (ip) inet_ntop(AF_INET,(void*)&(s->sin_addr),ip,ip_len);
        if (port) *port = ntohs(s->sin_port);
    }
	else if (sa.ss_family == AF_UNIX) 
	{
        if (ip) strncpy(ip,"/unixsocket",ip_len);
        if (port) *port = 0;
    } 
	else 
	{
        goto error;
    }
    return 0;

error:
    if (ip)
	{
        if (ip_len >= 2) 
		{
            ip[0] = '?';
            ip[1] = '\0';
        }
		else if (ip_len == 1)
		{
            ip[0] = '\0';
        }
    }
    if (port) *port = 0;
    return -1;
}

int ae_net_format_addr(char *buf, size_t buf_len, char *ip, int port)
{
    return snprintf(buf,buf_len, strchr(ip,':') ? "[%s]:%d" : "%s:%d", ip, port);
}

int ae_net_format_peer(int fd, char *buf, size_t buf_len)
{
    char ip[INET6_ADDRSTRLEN];
    int port;

    ae_net_peer_to_string(fd,ip,sizeof(ip),&port);
    return ae_net_format_addr(buf, buf_len, ip, port);
}

int ae_net_sock_name(int fd, char *ip, size_t ip_len, int *port) 
{
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);

    if (getsockname(fd,(struct sockaddr*)&sa,&salen) == -1)
	{
        if (port) *port = 0;
        ip[0] = '?';
        ip[1] = '\0';
        return -1;
    }
    if (sa.ss_family == AF_INET)
	{
        struct sockaddr_in *s = (struct sockaddr_in *)&sa;
        if (ip) inet_ntop(AF_INET,(void*)&(s->sin_addr),ip,ip_len);
        if (port) *port = ntohs(s->sin_port);
    }
    return 0;
}

int ae_net_format_sock(int fd, char *fmt, size_t fmt_len)
{
    char ip[INET6_ADDRSTRLEN];
    int port;
    ae_net_sock_name(fd,ip,sizeof(ip),&port);
    return ae_net_format_addr(fmt, fmt_len, ip, port);
}
