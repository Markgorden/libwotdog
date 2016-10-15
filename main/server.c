/*
 */

#include "server.h"


SERVER_CONTENT g_server_content; /* server global state */

unsigned int dictSdsHash(const void *key) 
{
	return dictGenHashFunction((unsigned char*)key, strlen((char*)key));
}

int dictClientPtrCompare(void * privdata,const void * key1,const void * key2)
{
	DICT_NOTUSED(privdata);
	CLIENT * a,* b;
	a = (CLIENT*)key1;
	b = (CLIENT*)key2;
	return a->id == b->id;
}

int dictClientHnadlerPtrCompare(void * privdata,const void * key1,const void * key2)
{
	DICT_NOTUSED(privdata);
	CLIENT_HANDLER * a,* b;
	a = (CLIENT_HANDLER*)key1;
	b = (CLIENT_HANDLER*)key2;
	return a->client_type == b->client_type;
}

static dictType KeyClientPtrDictType = {dictSdsHash, NULL, NULL, dictClientPtrCompare, NULL, NULL};
static dictType KeyClientHanderPtrDictType = {dictSdsHash, NULL, NULL, dictClientHnadlerPtrCompare, NULL, NULL};

#define MAX_ACCEPTS_PER_CALL 1000
static void accept_common_handler(int fd, int flags, char *ip) 
{
	SERVER_CONTENT * c = &g_server_content;
	CLIENT * client;
	if ((client = create_client(fd)) == NULL) 
	{
		serverLog(LL_WARNING,
			"Error registering fd event for the new client: %s (fd=%d)",
			strerror(errno),fd);
		close(fd); /* May be already closed, just ignore errors */
		return;
	}

	//if (dictSize(c->net.clients) > c->maxclients) 
	//{
	//	char *err = "-ERR max number of clients reached\r\n";
	//	// д���ĸ��߿ͻ���ȥ����ķ�������
	//	if (write(client->fd,err,strlen(err)) == -1) 
	//	{
	//		;/* Nothing to do, Just to avoid the warning... */
	//	}
	//	c->net.stat_rejected_conn++;
	//	free_client(client);
	//	return;
	//}
	if (fd != -1) set_element(c->net.clients,client->id, client);
	c->net.stat_numconnections++;
	client->flags |= flags;
}

void accept_tcp_handler(AE_EVENT_LOOP *el, int fd, void *privdata, int mask) 
{
	SERVER_CONTENT * c = &g_server_content;
	int cport, cfd, max = MAX_ACCEPTS_PER_CALL;
	char cip[NET_IP_STR_LEN];
	UNUSED(el);
	UNUSED(mask);
	UNUSED(privdata);

	while(max--) {
		cfd = ae_net_tcp_accept(c->net.neterr, fd, cip, sizeof(cip), &cport);
		if (cfd == AE_NET_ERR) {
			if (errno != EWOULDBLOCK)
				printf("Accepting client connection: %s\n", c->net.neterr);
			return;
		}
		serverLog(LL_VERBOSE,"Accepted %s:%d", cip, cport);
		accept_common_handler(cfd,0,cip);
	}
}

void accept_unix_handler(AE_EVENT_LOOP * el, int fd, void * privdata, int mask) 
{
	SERVER_CONTENT * c = &g_server_content;
	int cfd, max = MAX_ACCEPTS_PER_CALL;
	UNUSED(el);
	UNUSED(mask);
	UNUSED(privdata);

	while(max--) {
		cfd = ae_net_unix_accept(c->net.neterr, fd);
		if (cfd == AE_NET_ERR) {
			if (errno != EWOULDBLOCK)
				serverLog(LL_WARNING,
				"Accepting client connection: %s", c->net.neterr);
			return;
		}
		//serverLog(LL_VERBOSE,"Accepted connection to %s", c->net.unixsocket);
		accept_common_handler(cfd,CLIENT_UNIX_SOCKET,NULL);
	}
}


int listen_to_port(int port, int *fds, int *count) 
{
    SERVER_CONTENT * c = &g_server_content;
	int j;
    if (c->net.bindaddr_count == 0) 
		c->net.bindaddr[0] = NULL;
    for (j = 0; j < c->net.bindaddr_count || j == 0; j++) 
	{
         /* bind ipv4 address. */
        fds[*count] = ae_net_tcp_server(c->net.neterr,port,c->net.bindaddr[j],c->net.tcp_backlog);
        if (fds[*count] == AE_NET_ERR)
		{
            serverLog(LL_WARNING,
                "creating server tcp listening socket %s:%d: %s",
                c->net.bindaddr[j] ? c->net.bindaddr[j] : "*",
                port, c->net.neterr);
            return AE_NET_ERR;
        }
        ae_net_non_block(NULL,fds[*count]);
        (*count)++;
    }
    return C_OK;
}

void init_server(void) 
{
    SERVER_CONTENT * c = &g_server_content;
	int j;
    c->common.pid = getpid();
    c->common.client_handler = dictCreate(&KeyClientHanderPtrDictType,NULL);
	c->common.client_handler = listCreate();
	//c->net.current_client = NULL;
    c->net.clients = dictCreate(&KeyClientPtrDictType,NULL);
    c->net.clients_to_close = listCreate();
	// ��ʼ��������
	c->net.el = ae_create_event_loop(c->maxclients+CONFIG_FDSET_INCR);
    if (c->net.port != 0 &&
        listen_to_port(c->net.port, c->net.ipfd, &c->net.ipfd_count) == C_ERR)
        exit(1);

 //   if (c->net.unixsocket != NULL) 
	//{
 //       unlink(c->net.unixsocket); 
 //       c->net.sofd = ae_net_unix_server(c->net.neterr,c->net.unixsocket,
 //           c->net.unixsocketperm, c->net.tcp_backlog);
 //       if (c->net.sofd == AE_NET_ERR) {
 //           serverLog(LL_WARNING, "Opening Unix socket: %s", c->net.neterr);
 //           exit(1);
 //       }
 //       ae_net_non_block(NULL,c->net.sofd);
 //   }

 //   if (c->net.ipfd_count == 0 && c->net.sofd < 0) 
	//{
 //       serverLog(LL_WARNING, "Configured to not listen anywhere, exiting.");
 //       exit(1);
 //   }

	update_cached_time();

    if(ae_create_time_event(c->net.el, 1, server_cron, NULL, NULL) == AE_ERR) 
	{
        serverLog(LL_WARNING,"Can't create the serverCron time event.");
        exit(1);
    }

	for (j = 0; j < c->net.ipfd_count; j++) 
	{
        if (ae_create_file_event(c->net.el, c->net.ipfd[j], AE_READABLE,
            accept_tcp_handler,NULL) == AE_ERR)
            {
                serverLog(LL_WARNING,"Unrecoverable error creating server.ipfd file event.");
            }
    }
  //  if (c->net.sofd > 0 && ae_create_file_event(c->net.el,c->net.sofd,AE_READABLE,
		//accept_unix_handler,NULL) == AE_ERR) 
		//serverLog(LL_WARNING,"Unrecoverable error creating server.sofd file event.");
    //bio_init();
}

/* Write event handler. Just send data to the client. */
void write_handler_to_client(AE_EVENT_LOOP * el, int fd, void * privdata, int mask)
{
	UNUSED(el);
	UNUSED(mask);
	write_to_client(fd);
}

void before_sleep(struct AE_EVENT_LOOP * eventLoop) 
{
	UNUSED(eventLoop);
	SERVER_CONTENT * c = &g_server_content;
	if(ae_create_file_event(c->net.el, c->net.fd, AE_WRITABLE,write_handler_to_client, NULL) == AE_ERR)
	{
		printf("Error create file event...%s\n",__func__);
	}
}

void create_pid_file(void) 
{
    SERVER_CONTENT * c = &g_server_content;
	if (!c->common.pidfile) c->common.pidfile = zstrdup(CONFIG_DEFAULT_PID_FILE);
    FILE *fp = fopen(c->common.pidfile,"w");
    if (fp) 
	{
        fprintf(fp,"%d\n",(int)getpid());
        fclose(fp);
    }
}

#  define STDERR_FILENO 2
void daemonize(void) 
{
	int fd;
    if (fork() != 0) exit(0); 
    setsid(); 
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1)
	{
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) 
			close(fd);
    }
}

void add_client_handler(CLIENT_HANDLER_LIST * p)
{
	SERVER_CONTENT * c = &g_server_content;
	CLIENT_HANDLER * cli_handler = malloc(sizeof(CLIENT_HANDLER));
	COMMAND_CLIENT_HANDLER * cmd_cli_handler = malloc(sizeof(COMMAND_CLIENT_HANDLER));
	memcpy(cli_handler->sub_client_handler,p->client_handler->sub_client_handler,sizeof(COMMAND_CLIENT_HANDLER));
	memcpy(cli_handler,p->client_handler,sizeof(CLIENT_HANDLER));
	cli_handler->sub_client_handler = cmd_cli_handler;
	listAddNodeTail(c->common.client_handler,cli_handler);
}

int main(int argc, char ** argv) 
{
    SERVER_CONTENT * c = &g_server_content;
    struct timeval tv;
    int j;
    setlocale(LC_COLLATE,"");
    zmalloc_enable_thread_safeness();
    zmalloc_set_oom_handler(NULL); //bug report to "dash board"
    srand(time(NULL)^getpid());
    gettimeofday(&tv,NULL);
    dictSetHashFunctionSeed(tv.tv_sec^tv.tv_usec^getpid());
    init_server();
	// ���ӷ�������Ҫ������Э��handler
	
	COMMAND_CLIENT_HANDLER cch ;
	cch.a = 0;
	cch.b = 0;
	cch.c = 0;
	cch.d = 0;
	
	CLIENT_HANDLER_LIST p;
	p.client_handler->parse_recved_data = parse_command_recved_data;
	p.client_handler->sub_client_handler = &cch;
	p.client_type = COMMAND_CLIENT;
	p.magic = PROTOCOL_MAGIC;
	add_client_handler(&p);

    // ���������ѭ��
	ae_set_before_sleep_proc(c->net.el,before_sleep);
	ae_main(c->net.el);
    ae_delete_event_loop(c->net.el);
    return 0;
}