/* Linux epoll(2) based ae.c module
 *
 */

#include <sys/epoll.h>

typedef struct __tag_api_state {
    int epfd;
    struct epoll_event *events;
} API_STATE;

static int api_create(AE_EVENT_LOOP * event_loop) {
    API_STATE *state = zmalloc(sizeof(API_STATE));

    if (!state) return -1;
    state->events = zmalloc(sizeof(struct epoll_event)*event_loop->set_size);
    if (!state->events) {
        zfree(state);
        return -1;
    }
    state->epfd = epoll_create(1024); /* 1024 is just a hint for the kernel */
    if (state->epfd == -1) {
        zfree(state->events);
        zfree(state);
        return -1;
    }
    event_loop->api_data = state;
    return 0;
}

static int api_resize(AE_EVENT_LOOP * event_loop, int set_size) {
    API_STATE *state = event_loop->api_data;

    state->events = zrealloc(state->events, sizeof(struct epoll_event)*set_size);
    return 0;
}

static void api_free(AE_EVENT_LOOP * event_loop) {
    API_STATE *state = event_loop->api_data;

    close(state->epfd);
    zfree(state->events);
    zfree(state);
}

static int api_add_event(AE_EVENT_LOOP * event_loop, int fd, int mask) {
    API_STATE *state = event_loop->api_data;
    struct epoll_event ee = {0}; /* avoid valgrind warning */
    /* If the fd was already monitored for some event, we need a MOD
     * operation. Otherwise we need an ADD operation. */
    int op = event_loop->events[fd].mask == AE_NONE ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;

    ee.events = 0;
    mask |= event_loop->events[fd].mask; /* Merge old events */
    if (mask & AE_READABLE) ee.events |= EPOLLIN;
    if (mask & AE_WRITABLE) ee.events |= EPOLLOUT;
    ee.data.fd = fd;
    if (epoll_ctl(state->epfd,op,fd,&ee) == -1) return -1;
    return 0;
}

static void api_del_event(AE_EVENT_LOOP * event_loop, int fd, int delmask) {
    API_STATE * state = event_loop->api_data;
    struct epoll_event ee = {0}; /* avoid valgrind warning */
    int mask = event_loop->events[fd].mask & (~delmask);

    ee.events = 0;
    if (mask & AE_READABLE) ee.events |= EPOLLIN;
    if (mask & AE_WRITABLE) ee.events |= EPOLLOUT;
    ee.data.fd = fd;
    if (mask != AE_NONE) {
        epoll_ctl(state->epfd,EPOLL_CTL_MOD,fd,&ee);
    } else {
        /* Note, Kernel < 2.6.9 requires a non null event pointer even for
         * EPOLL_CTL_DEL. */
        epoll_ctl(state->epfd,EPOLL_CTL_DEL,fd,&ee);
    }
}

static int api_poll(AE_EVENT_LOOP * event_loop, struct timeval *tvp) 
{
    API_STATE *state = event_loop->api_data;
    int retval, numevents = 0;

    retval = epoll_wait(state->epfd,state->events,event_loop->set_size,
            tvp ? (tvp->tv_sec*1000 + tvp->tv_usec/1000) : -1);
    if (retval > 0) {
        int j;

        numevents = retval;
        for (j = 0; j < numevents; j++) {
            int mask = 0;
            struct epoll_event * e = state->events+j;

            if (e->events & EPOLLIN) mask |= AE_READABLE;
            if (e->events & EPOLLOUT) mask |= AE_WRITABLE;
            if (e->events & EPOLLERR) mask |= AE_WRITABLE;
            if (e->events & EPOLLHUP) mask |= AE_WRITABLE;
            event_loop->fired[j].fd = e->data.fd;
            event_loop->fired[j].mask = mask;
        }
    }
    return numevents;
}

static char *api_name(void) {
    return "epoll";
}
