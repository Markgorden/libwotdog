#include "server.h"

#define run_with_period(_ms_) if ((_ms_ <= 1000/g_server_content.common.hz) || !(g_server_content.common.cronloops%((_ms_)/(1000/g_server_content.common.hz))))
#define PROTO_MBULK_BIG_ARG     (1024*32)
/* Return the UNIX time in microseconds */
long long ustime(void) 
{
	struct timeval tv;
	long long ust;

	gettimeofday(&tv, NULL);
	ust = ((long long)tv.tv_sec)*1000000;
	ust += tv.tv_usec;
	return ust;
}

/* Return the UNIX time in milliseconds */
mstime_t mstime(void) 
{
	return ustime()/1000;
}

void update_cached_time(void) 
{
	SERVER_CONTENT * c = &g_server_content;
	c->unixtime = time(NULL);
	c->mstime = mstime();
}

unsigned int get_lru_clock(void) 
{
	return (mstime()/LRU_CLOCK_RESOLUTION) & LRU_CLOCK_MAX;
}

int clients_cron_handle_timeout(CLIENT * client, mstime_t now_ms) 
{
    SERVER_CONTENT * c = &g_server_content;
	time_t now = now_ms/1000;
    if (c->config.maxidletime &&
        !(client->flags & CLIENT_TRANSVERTER) &&   
        !(client->flags & CLIENT_OTHER) &&   
        !(client->flags & CLIENT_OTHER_SERVER) &&  
        !(client->flags & CLIENT_PUBSUB) &&   
        (now - client->lastinteraction > c->config.maxidletime))
    {
        printf("Closing idle client\n");
        free_client(client);
        return 1;
    }
    return 0;
}

int clients_cron_resize_query_buffer(CLIENT * client) 
{
	if (client == NULL)
		return false;
	SERVER_CONTENT * c = &g_server_content;   
	size_t querybuf_size = sdsAllocSize(client->querybuf);
    time_t idletime = c->unixtime - client->lastinteraction;

    if (((querybuf_size > PROTO_MBULK_BIG_ARG) &&
         (querybuf_size/(client->querybuf_peak+1)) > 2) ||
         (querybuf_size > 1024 && idletime > 2))
    {
        if (sdsavail(client->querybuf) > 1024) 
		{
            client->querybuf = sdsRemoveFreeSpace(client->querybuf);
        }
    }
    client->querybuf_peak = 0;
    return 0;
}

#define CLIENTS_CRON_MIN_ITERATIONS 5
void clients_cron(void) 
{
	SERVER_CONTENT * c = &g_server_content;   
    int numclients = dictSize(c->net.clients);
	
	if (0 == numclients) return;
	
	if (c->common.hz == 0) c->common.hz = 1;

    int iterations = numclients/c->common.hz;
    mstime_t now = mstime();

	if (iterations < CLIENTS_CRON_MIN_ITERATIONS)
        iterations = (numclients < CLIENTS_CRON_MIN_ITERATIONS) ?
                     numclients : CLIENTS_CRON_MIN_ITERATIONS;

	dictIterator * di = dictGetIterator(c->net.clients);
	dictEntry * de;
	CLIENT * client = 0;

	while((de = dictNext(di)) != NULL && iterations--) 
	{
		client = (CLIENT *)dictGetVal(de);
	}
	dictReleaseIterator(di);
    if (clients_cron_handle_timeout(client,now)) 
		;//continue;
    if (clients_cron_resize_query_buffer(client))
		;//continue;
	write_to_client(client);
}

//--------------------------------------------------------
/* Hash table parameters */
#define HASHTABLE_MIN_FILL        10      /* Minimal hash table fill 10% */
int htNeedsResize(dict * dict) 
{
	long long size, used;
	size = dictSlots(dict);
	used = dictSize(dict);
	return (size > DICT_HT_INITIAL_SIZE && (used*100/size < HASHTABLE_MIN_FILL));
}

/* If the percentage of used slots in the HT reaches HASHTABLE_MIN_FILL
 * we resize the hash table to save memory */
void try_resize_hash_tables(dict * d) 
{
    if (htNeedsResize(d))
        dictResize(d);
}

int incrementally_rehash(dict * d) 
{
	if (dictIsRehashing(d)) 
	{
		dictRehashMilliseconds(d,1);
		return 1; /* already used our millisecond for this loop... */
	}
	return 0;
}

void hashtable_cron(void) 
{
    SERVER_CONTENT * c = &g_server_content;
	try_resize_hash_tables(c->net.clients);
	incrementally_rehash(c->net.clients);
}


void free_clients_in_async_free_queue(void) 
{
	SERVER_CONTENT * c = &g_server_content;
	while (listLength(c->net.clients_to_close)) 
	{
		listNode * ln = listFirst(c->net.clients_to_close);
		CLIENT * client = listNodeValue(ln);
		free_client(client);
		listDelNode(c->net.clients_to_close,ln);
	}
}

int server_cron(struct AE_EVENT_LOOP * event_loop, long long id, void * client_data) 
{
    SERVER_CONTENT * c = &g_server_content;
	int j;
    UNUSED(event_loop);
    UNUSED(id);
    UNUSED(client_data);
	if (c->common.hz == 0) c->common.hz = 1;

	printf("this is a server_cron!\n");
    update_cached_time();
    c->lruclock = get_lru_clock();
	run_with_period(5000) {
            long long size, used, vkeys;
            size = dictSlots(c->net.clients);
            used = dictSize(c->net.clients);
            if (used) 
			{
                printf("%lld clients connected in %lld slots HT.%zu bytes in use",used, size,zmalloc_used_memory());
            }
			printf("run_with_period--------------------\n");
    }
    clients_cron();
	hashtable_cron();
    /* Close clients that need to be closed asynchronous */
    free_clients_in_async_free_queue();
	c->common.cronloops++;
    return 1000/c->common.hz;
}

