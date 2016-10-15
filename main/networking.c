/*
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
		(unsigned long long) listLength(client->reply),
		events
		);
}


bool probe_procotol_packet(CLIENT * client)
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
		return false;
	}
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
	else if (probe_procotol_packet(client))	
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
		if (!parse_temp_recved_data(client))
			goto error;
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
	if (ae_create_file_event(content->net.el,fd,AE_READABLE,read_handler_for_client, c) == AE_ERR)
	{
		close(fd);
		zfree(c);
		return NULL;
	}
	//c->id = content->net.next_client_id++;
	c->fd = fd;
	c->querybuf = sdsempty();
	c->querybuf_peak = 0;
	c->reqtype = 0;
    c->flags = 0;
    c->ctime = c->lastinteraction = content->unixtime;
    c->authenticated = 0;
	if (fd != -1) 
		;//int retval = set_element(content->net.clients, key, c);
    return c;
}

void unlink_client(CLIENT * client) 
{
    SERVER_CONTENT * c = &g_server_content;
	if (c->net.current_client == c) c->net.current_client = NULL;
    if (client->fd != -1) 
	{
        delete_element(c->net.clients, client->id);
        ae_delete_file_event(c->net.el,client->fd,AE_READABLE);
        ae_delete_file_event(c->net.el,client->fd,AE_WRITABLE);
        close(client->fd);
        client->fd = -1;
    }
}

void free_client(CLIENT * client) 
{
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

int client_has_pending_replies(CLIENT * client) 
{
	return client->bufpos || listLength(client->reply);
}

int write_to_client(int fd, CLIENT * client, int handler_installed) 
{
    SERVER_CONTENT * c = &g_server_content;
	ssize_t nwritten = 0, totwritten = 0;
    size_t objlen;
    size_t objmem;
	void * o;
	// .....

    while(client_has_pending_replies(client)) 
	{
        if (client->bufpos > 0) 
		{
            nwritten = write(fd,client->buf + client->sentlen, client->bufpos - client->sentlen);
            if (nwritten <= 0) break;
            client->sentlen += nwritten;
            totwritten += nwritten;
            if ((int)client->sentlen == client->bufpos) 
			{
                client->bufpos = 0;
                client->sentlen = 0;
            }
        } 
		else 
		{
            o = listNodeValue(listFirst(client->reply));
            // objlen = sdslen(o->ptr);
            if (objlen == 0) 
			{
                listDelNode(client->reply,listFirst(client->reply));
                client->reply_bytes -= objmem;
                continue;
            }

           // nwritten = write(fd, ((char*)o->ptr)+ client->sentlen,objlen - client->sentlen);
            if (nwritten <= 0) break;
            client->sentlen += nwritten;
            totwritten += nwritten;
            if (client->sentlen == objlen) 
			{
                listDelNode(client->reply,listFirst(client->reply));
                client->sentlen = 0;
                client->reply_bytes -= objmem;
            }
        }
        c->log.stat_net_output_bytes += totwritten;
        if (totwritten > NET_MAX_WRITES_PER_EVENT && (c->maxmemory == 0 ||
             zmalloc_used_memory() < c->maxmemory)) 
			 break;
    }
    if (nwritten == -1) 
	{
        if (errno == EAGAIN) 
		{
            nwritten = 0;
        } 
		else 
		{
            serverLog(LL_VERBOSE,"Error writing to client: %s", strerror(errno));
            free_client(client);
            return C_ERR;
        }
    }
    if (totwritten > 0) 
	{
        if (!(client->flags & CLIENT_MASTER)) 
			client->lastinteraction = c->unixtime;
    }
    if (!client_has_pending_replies(client)) 
	{
        client->sentlen = 0;
        if (handler_installed) ae_delete_file_event(c->net.el, client->fd,AE_WRITABLE);
        if (client->flags & CLIENT_CLOSE_AFTER_REPLY) 
		{
            free_client(client);
            return C_ERR;
        }
    }
    return C_OK;
}



void reset_client(CLIENT *c) 
{
    c->reqtype = 0;
}







