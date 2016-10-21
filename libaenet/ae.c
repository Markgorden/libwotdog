/* A simple event-driven programming library. 
 * Originally I wrote this code for the Jim's event-loop 
 * (Jim is a Tcl interpreter) but later translated it in form of a library for easy reuse.
 */

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "ae.h"
#include "zmalloc.h"

#ifdef HAVE_EPOLL
  #include "epoll.c"
#else
  #include "select.c"
#endif

AE_EVENT_LOOP * ae_create_event_loop(int set_size) 
{
    AE_EVENT_LOOP * event_loop;
    int i;
    if ((event_loop = zmalloc(sizeof(*event_loop))) == NULL) goto err;
    event_loop->events = zmalloc(sizeof(AE_EVENT_LOOP)*set_size);
    event_loop->fired = zmalloc(sizeof(AE_EVENT_LOOP)*set_size);
    if (event_loop->events == NULL || event_loop->fired == NULL) goto err;
    event_loop->set_size = set_size;
    event_loop->last_time = time(NULL);
    event_loop->time_event_head = NULL;
    event_loop->time_event_next_id = 0;
    event_loop->stop = 0;
    event_loop->max_fd = -1;
    event_loop->before_sleep = NULL;
    if (api_create(event_loop) == -1) goto err;
    for (i = 0; i < set_size; i++)
        event_loop->events[i].mask = AE_NONE;
    return event_loop;

err:
    if (event_loop) 
	{
        zfree(event_loop->events);
        zfree(event_loop->fired);
        zfree(event_loop);
    }
    return NULL;
}

int ae_get_set_size(AE_EVENT_LOOP * event_loop) 
{
    return event_loop->set_size;
}

int ae_resize_set_size(AE_EVENT_LOOP * event_loop, int set_size) 
{
    int i;

    if (set_size == event_loop->set_size) return AE_OK;
    if (event_loop->max_fd >= set_size) return AE_ERR;
    if (api_resize(event_loop,set_size) == -1) 
		return AE_ERR;
    event_loop->events = zrealloc(event_loop->events,sizeof(AE_FILE_EVENT)*set_size);
    event_loop->fired = zrealloc(event_loop->fired,sizeof(AE_FIRE_EVENT)*set_size);
    event_loop->set_size = set_size;
    for (i = event_loop->max_fd+1; i < set_size; i++)
        event_loop->events[i].mask = AE_NONE;
    return AE_OK;
}

void ae_delete_event_loop(AE_EVENT_LOOP * event_loop) 
{
    api_free(event_loop);
    zfree(event_loop->events);
    zfree(event_loop->fired);
    zfree(event_loop);
}

void ae_stop(AE_EVENT_LOOP * event_loop) 
{
    event_loop->stop = 1;
}

int ae_create_file_event(AE_EVENT_LOOP * event_loop, int fd, int mask,AeFileProc * proc, void *client_data)
{
    if (fd >= event_loop->set_size) 
	{
        errno = ERANGE;
        return AE_ERR;
    }

    AE_FILE_EVENT *fe = &event_loop->events[fd];

    if (api_add_event(event_loop, fd, mask) == -1)
        return AE_ERR;
    fe->mask |= mask;
    if (mask & AE_READABLE) 
		fe->rfile_proc = proc;
    if (mask & AE_WRITABLE) 
		fe->wfile_proc = proc;
    fe->client_data = client_data;
    if (fd > event_loop->max_fd)
        event_loop->max_fd = fd;
    return AE_OK;
}

void ae_delete_file_event(AE_EVENT_LOOP * event_loop, int fd, int mask)
{
    if (fd >= event_loop->set_size) return;
    AE_FILE_EVENT * fe = &event_loop->events[fd];
    if (fe->mask == AE_NONE) return;

    api_del_event(event_loop, fd, mask);
    fe->mask = fe->mask & (~mask);
    if (fd == event_loop->max_fd && fe->mask == AE_NONE) 
	{
        int j;

        for (j = event_loop->max_fd-1; j >= 0; j--)
            if (event_loop->events[j].mask != AE_NONE) break;
        event_loop->max_fd = j;
    }
}

int ae_get_file_events(AE_EVENT_LOOP * event_loop, int fd) 
{
    if (fd >= event_loop->set_size) return 0;
    AE_FILE_EVENT * fe = &event_loop->events[fd];
    return fe->mask;
}

static inline void get_time(long *seconds, long *milliseconds)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    *seconds = tv.tv_sec;
    *milliseconds = tv.tv_usec/1000;
}

static inline void add_milliseconds_to_now(long long milliseconds, long *sec, long *ms) 
{
    long cur_sec, cur_ms, when_sec, when_ms;

    get_time(&cur_sec, &cur_ms);
    when_sec = cur_sec + milliseconds/1000;
    when_ms = cur_ms + milliseconds%1000;
    if (when_ms >= 1000) {
        when_sec ++;
        when_ms -= 1000;
    }
    *sec = when_sec;
    *ms = when_ms;
}

long long ae_create_time_event(AE_EVENT_LOOP * event_loop, long long milliseconds, AeTimeProc *proc, void *client_data,AeEventFinalizerProc *finalizer_proc)
{
    long long id = event_loop->time_event_next_id++;
    AE_TIME_EVENT * te;

    te = zmalloc(sizeof(*te));
    if (te == NULL) return AE_ERR;
    te->id = id;
    add_milliseconds_to_now(milliseconds,&te->when_sec,&te->when_ms);
    te->time_proc = proc;
    te->finalizer_proc = finalizer_proc;
    te->client_data = client_data;
    te->next = event_loop->time_event_head;
    event_loop->time_event_head = te;
    return id;
}

int ae_delete_time_event(AE_EVENT_LOOP * event_loop, long long id)
{
    AE_TIME_EVENT *te = event_loop->time_event_head;
    while(te) {
        if (te->id == id) {
            te->id = AE_DELETED_EVENT_ID;
            return AE_OK;
        }
        te = te->next;
    }
    return AE_ERR; 
}

static inline AE_TIME_EVENT * search_nearest_timer(AE_EVENT_LOOP * event_loop)
{
    AE_TIME_EVENT *te = event_loop->time_event_head;
    AE_TIME_EVENT *nearest = NULL;

    while(te) {
        if (!nearest || te->when_sec < nearest->when_sec ||
                (te->when_sec == nearest->when_sec &&
                 te->when_ms < nearest->when_ms))
            nearest = te;
        te = te->next;
    }
    return nearest;
}

static int inline process_time_events(AE_EVENT_LOOP * event_loop) 
{
    int processed = 0;
    AE_TIME_EVENT * te, * prev;
    long long maxId;
    time_t now = time(NULL);

	if (now < event_loop->last_time) {
        te = event_loop->time_event_head;
        while(te) {
            te->when_sec = 0;
            te = te->next;
        }
    }
    event_loop->last_time = now;

    prev = NULL;
    te = event_loop->time_event_head;
    maxId = event_loop->time_event_next_id - 1;
    while(te) {
        long now_sec, now_ms;
        long long id;

        if (te->id == AE_DELETED_EVENT_ID) {
           AE_TIME_EVENT *next = te->next;
            if (prev == NULL)
                event_loop->time_event_head = te->next;
            else
                prev->next = te->next;
            if (te->finalizer_proc)
                te->finalizer_proc(event_loop, te->client_data);
            zfree(te);
            te = next;
            continue;
        }

        if (te->id > maxId) {
            te = te->next;
            continue;
        }
        get_time(&now_sec, &now_ms);
        if (now_sec > te->when_sec ||
            (now_sec == te->when_sec && now_ms >= te->when_ms))
        {
            int retval;

            id = te->id;
            retval = te->time_proc(event_loop, id, te->client_data);
            processed++;
            if (retval != AE_NOMORE) {
                add_milliseconds_to_now(retval,&te->when_sec,&te->when_ms);
            } else {
                te->id = AE_DELETED_EVENT_ID;
            }
        }
        prev = te;
        te = te->next;
    }
    return processed;
}

int ae_process_events(AE_EVENT_LOOP * event_loop, int flags)
{
    int processed = 0, numevents;

    if (!(flags & AE_TIME_EVENTS) && !(flags & AE_FILE_EVENTS)) return 0;

    if (event_loop->max_fd != -1 || ((flags & AE_TIME_EVENTS) && !(flags & AE_DONT_WAIT))) 
	{
        int j;
        AE_TIME_EVENT *shortest = NULL;
        struct timeval tv, *tvp;

        if (flags & AE_TIME_EVENTS && !(flags & AE_DONT_WAIT))
            shortest = search_nearest_timer(event_loop);
        if (shortest) 
		{
            long now_sec, now_ms;

            get_time(&now_sec, &now_ms);
            tvp = &tv;

            long long ms =
                (shortest->when_sec - now_sec)*1000 +
                shortest->when_ms - now_ms;

            if (ms > 0) {
                tvp->tv_sec = ms/1000;
                tvp->tv_usec = (ms % 1000)*1000;
            } else {
                tvp->tv_sec = 0;
                tvp->tv_usec = 0;
            }
        } 
		else 
		{
            if (flags & AE_DONT_WAIT) {
                tv.tv_sec = tv.tv_usec = 0;
                tvp = &tv;
            } 
			else 
			{
                tvp = NULL; 
            }
        }

        numevents = api_poll(event_loop, tvp);
        for (j = 0; j < numevents; j++) 
		{
            AE_FILE_EVENT * fe = &event_loop->events[event_loop->fired[j].fd];
            int mask = event_loop->fired[j].mask;
            int fd = event_loop->fired[j].fd;
            int rfired = 0;

            if (fe->mask & mask & AE_READABLE) 
			{
                rfired = 1;
                fe->rfile_proc(event_loop,fd,fe->client_data,mask);
            }
            if (fe->mask & mask & AE_WRITABLE) 
			{
                if (!rfired || fe->wfile_proc != fe->rfile_proc)
                    fe->wfile_proc(event_loop,fd,fe->client_data,mask);
            }
            processed++;
        }
    }

    if (flags & AE_TIME_EVENTS)
        processed += process_time_events(event_loop);

    return processed;
}

int ae_wait(int fd, int mask, long long milliseconds) 
{
    struct pollfd pfd;
    int retmask = 0, retval;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    if (mask & AE_READABLE) pfd.events |= POLLIN;
    if (mask & AE_WRITABLE) pfd.events |= POLLOUT;

    if ((retval = poll(&pfd, 1, milliseconds))== 1) {
        if (pfd.revents & POLLIN) retmask |= AE_READABLE;
        if (pfd.revents & POLLOUT) retmask |= AE_WRITABLE;
	if (pfd.revents & POLLERR) retmask |= AE_WRITABLE;
        if (pfd.revents & POLLHUP) retmask |= AE_WRITABLE;
        return retmask;
    } else {
        return retval;
    }
}

void ae_main(AE_EVENT_LOOP * event_loop) 
{
    //event_loop->stop = 0;
    while (!event_loop->stop)  
	{
       // dynamic adjust the loop events capacity
		if ((event_loop->max_fd >> 1) > event_loop->set_size )
			ae_resize_set_size(event_loop,event_loop->set_size * 2);
		if (event_loop->before_sleep != NULL)
            event_loop->before_sleep(event_loop);
        ae_process_events(event_loop, AE_ALL_EVENTS);
    }
}

char * ae_get_api_name(void) 
{
    return api_name();
}

void ae_set_before_sleep_proc(AE_EVENT_LOOP * event_loop, AeBeforeSleepProc *before_sleep) 
{
    event_loop->before_sleep = before_sleep;
}

