/*
 Authors: ZhangXuelian
 	


 Changes:
 	
	
*/

#include "server.h"
#include <sys/uio.h>
#include <math.h>

void gen_client_peer_id(CLIENT *client, char *peerid,size_t peerid_len) 
{
	ae_net_format_peer(client->fd,peerid,peerid_len);
}

char * get_client_peer_id(CLIENT * client) 
{
	char peerid[NET_PEER_ID_LEN];
	if (client->peerid == NULL) 
	{
		gen_client_peer_id(client,peerid,sizeof(peerid));
		client->peerid = sdsnew(peerid);
	}
	return client->peerid;
}

sds cat_client_info_string(sds s, CLIENT * client) 
{
	SERVER_CONTENT * c = &g_server_content;
	char flags[16], events[3], *p;
	int emask;
	p = flags;
	emask = client->fd == -1 ? 0 : ae_get_file_events(c->net.el,client->fd);
	p = events;
	if (emask & AE_READABLE) *p++ = 'r';
	if (emask & AE_WRITABLE) *p++ = 'w';
	*p = '\0';
	return sdscatfmt(s,
		"id=%U addr=%s fd=%i name=%s age=%I idle=%I flags=%s db=%i qbuf=%U qbuf-free=%U obl=%U oll=%U events=%s",
		(unsigned long long) client->id,
		get_client_peer_id(client),
		client->fd,
		"",
		(long long)(c->unixtime - client->ctime),
		(long long)(c->unixtime - client->lastinteraction),
		flags,
		0,
		(unsigned long long) sdslen(client->querybuf),
		(unsigned long long) sdsavail(client->querybuf),
		(unsigned long long) client->bufpos,
		0,
		events
		);
}


bool probe_protocol_packet(CLIENT * client)
{
	SERVER_CONTENT * c = &g_server_content;
	listNode *ln;
	listIter li;
	listRewind(c->common.client_handler,&li);
	while ((ln = listNext(&li)) != NULL) 
	{
		CLIENT_HANDLER_LIST * cac = (CLIENT_HANDLER_LIST*)ln->value;
		if (sdslen(client->querybuf) >= MAGIC_LENGTH)
		{
			if (! memcmp(client->querybuf, &cac->magic, MAGIC_LENGTH))
			{
				client->reqtype = cac->client_type;
				client->client_handler = cac->client_handler;
				return true;
			}
		}
	}
	return false;
}

static inline bool parse_temp_recved_data(CLIENT * client)
{
	printf("%s:%d\n", __func__, 1);

	if (((sdslen(client->querybuf) >= 4) && (0 == strncasecmp(client->querybuf, "GET ", 4))) ||
		((sdslen(client->querybuf) >= 5) && (0 == strncasecmp(client->querybuf, "POST ", 5))))
	{
		client->reqtype = HTTP_CLIENT;
		client->client_handler = 0; // 这是一个Http客户端。内置客户端。
	}
	else if (probe_protocol_packet(client))	
	{
		printf("probe protocol connect req\n");
		return client->client_handler->parse_recved_data(client);
	}
	return false;
}

void process_input_buffer(CLIENT * client) 
{
	SERVER_CONTENT * c = &g_server_content;
	c->net.current_client = client;

	if (sdslen(client->querybuf) < 4)
	{
		return;
	}

	bool ret = false;
	if (client->reqtype == UNKNOWN_CLIENT)
	{
		if (!parse_temp_recved_data(client))
			goto error;
	}
	else
		// 用各自的私有协议处理器去处理。
		client->client_handler->parse_recved_data(client);
error:
	;
}

void read_handler_for_client(AE_EVENT_LOOP * el, int fd, void *privdata, int mask) 
{
	SERVER_CONTENT * c = &g_server_content;
	CLIENT * client = (CLIENT*) privdata;
	int nread, readlen;
	size_t qblen;
	UNUSED(el);
	UNUSED(mask);
	readlen = PROTO_IOBUF_LEN;
	qblen = sdslen(client->querybuf);
	if (client->querybuf_peak < qblen) client->querybuf_peak = qblen;
	client->querybuf = sdsMakeRoomFor(client->querybuf, readlen);
	nread = read(fd, client->querybuf+qblen, readlen);
	if (nread == -1) 
	{
		if (errno == EAGAIN) 
		{
			return;
		} 
		else 
		{
			serverLog(LL_VERBOSE, "Reading from client: %s",strerror(errno));
			free_client(c);
			return;
		}
	} 
	else if (nread == 0) 
	{
		serverLog(LL_VERBOSE, "Client closed connection");
		free_client(c);
		return;
	}

	sdsIncrLen(client->querybuf,nread);
	client->lastinteraction = c->unixtime;
	c->log.stat_net_input_bytes += nread;
	if (sdslen(client->querybuf) > client->client_max_querybuf_len) 
	{
		sds ci = cat_client_info_string(sdsempty(),client), bytes = sdsempty();
		bytes = sdscatrepr(bytes,client->querybuf,64);
		serverLog(LL_WARNING,"Closing client that reached max query buffer length: %s (qbuf initial bytes: %s)", ci, bytes);
		sdsfree(ci);
		sdsfree(bytes);
		free_client(client);
		return;
	}
	process_input_buffer(client);
}

CLIENT * create_client(int fd) 
{
	SERVER_CONTENT * content = &g_server_content;
	CLIENT * c = zmalloc(sizeof(CLIENT));
	if (fd <= 0)
		return (CLIENT *)NULL;
	ae_net_non_block(NULL,fd);
	ae_net_enable_tcp_no_delay(NULL,fd);
	if (content->config.tcpkeepalive)
		ae_net_keep_alive(NULL,fd,content->config.tcpkeepalive);
	//if (ae_create_file_event(content->net.el, fd, AE_WRITABLE,
	//	send_reply_to_client, c) == AE_ERR)
	//	;
	if (ae_create_file_event(content->net.el,fd, AE_READABLE, 
		read_handler_for_client, c) == AE_ERR)
	{
		close(fd);
		zfree(c);
		return NULL;
	}
	c->fd = fd;
	c->querybuf = sdsempty();
	c->querybuf_peak = 0;
	c->reqtype = 0;
    c->flags = 0;
    c->ctime = c->lastinteraction = content->unixtime;
    c->authenticated = 0;
	c->buf_len = 0;
	c->buf = NULL;
	c->bufpos = 0;
	c->cmd_list = listCreate();
	init_protocol_context(&c->buf_list);
	if (fd != -1) 
		//int retval = set_element(content->net.clients_temp, fd, c);
    return c;
}

void unlink_client(CLIENT * client) 
{
 //   SERVER_CONTENT * c = &g_server_content;
	//if (c->net.current_client == c) c->net.current_client = NULL;
 //   if (client->fd != -1) 
	//{
 //       delete_element(c->net.clients, client->id);
 //       ae_delete_file_event(c->net.el,client->fd,AE_READABLE);
 //       ae_delete_file_event(c->net.el,client->fd,AE_WRITABLE);
 //       close(client->fd);
 //       client->fd = -1;
 //   }
}

void free_client(CLIENT * client) 
{
	return;
	sdsfree(client->querybuf);
    client->querybuf = NULL;
    //if (client->flags & CLIENT_BLOCKED) unblock_client(client);
    unlink_client(client);
    //zfree(client->argv);
    //sdsfree(client->peerid);
    zfree(client);
}

void free_client_async(CLIENT * client) 
{
    SERVER_CONTENT * c = &g_server_content;
	listAddNodeTail(c->net.clients_to_close,client);
}

void send_reply_to_client(AE_EVENT_LOOP * el, int fd, void * privdata, int mask)
{
	write_to_client((CLIENT *)privdata);
}

int write_to_client(CLIENT * c) 
{
	SERVER_CONTENT * content = &g_server_content;
	int fd = c->fd;
	int len;

	if (!c->buf_len)
	{
		c->bufpos = 0;
		//if (c->buf != NULL ) 
		//	zfree(c->buf);
		// get_protocol_packet_to_send(&c->buf_list, &c->buf, &c->buf_len);
	}

	while (c->buf_len)
	{
		if (c->buf_len)
		{
		len = send(fd, c->buf + c->bufpos, c->buf_len, MSG_NOSIGNAL);
		if (0 >= len)
		{
			printf("%s: send failed %d\n", __func__, 2);
			return false;
		}
		c->bufpos += len;
		c->buf_len -= len;
	}

		if (!c->buf_len)
		{
			c->bufpos = 0;
			//if (c->buf != NULL ) 
			//	zfree(c->buf);
			// get_protocol_packet_to_send(&c->buf_list, &c->buf, &c->buf_len);
		}
	}
	return 1;
}

void reset_client(CLIENT *c) 
{
    c->reqtype = 0;
}







