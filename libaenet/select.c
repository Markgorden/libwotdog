/* Select()-based ae.c module.
 *
 */


#include <sys/select.h>
#include <string.h>

typedef struct __tag_api_state {
    fd_set rfds, wfds;
    /* We need to have a copy of the fd sets as it's not safe to reuse
     * FD sets after select(). */
    fd_set _rfds, _wfds;
} API_STATE;

static int api_create(AE_EVENT_LOOP * event_loop) {
    API_STATE *state = zmalloc(sizeof(API_STATE));

    if (!state) return -1;
    FD_ZERO(&state->rfds);
    FD_ZERO(&state->wfds);
    event_loop->api_data = state;
    return 0;
}

static int api_resize(AE_EVENT_LOOP * event_loop, int setsize) {
    /* Just ensure we have enough room in the fd_set type. */
    if (setsize >= FD_SETSIZE) return -1;
    return 0;
}

static void api_free(AE_EVENT_LOOP * event_loop) {
    zfree(event_loop->api_data);
}

static int api_add_event(AE_EVENT_LOOP * event_loop, int fd, int mask) {
    API_STATE *state = event_loop->api_data;

    if (mask & AE_READABLE) FD_SET(fd,&state->rfds);
    if (mask & AE_WRITABLE) FD_SET(fd,&state->wfds);
    return 0;
}

static void api_del_event(AE_EVENT_LOOP * event_loop, int fd, int mask) {
    API_STATE *state = event_loop->api_data;

    if (mask & AE_READABLE) FD_CLR(fd,&state->rfds);
    if (mask & AE_WRITABLE) FD_CLR(fd,&state->wfds);
}

static int api_poll(AE_EVENT_LOOP * event_loop, struct timeval *tvp) {
    API_STATE *state = event_loop->api_data;
    int retval, j, numevents = 0;

    memcpy(&state->_rfds,&state->rfds,sizeof(fd_set));
    memcpy(&state->_wfds,&state->wfds,sizeof(fd_set));

    retval = select(event_loop->max_fd+1, &state->_rfds,&state->_wfds,NULL,tvp);
    if (retval > 0) {
        for (j = 0; j <= event_loop->max_fd; j++) {
            int mask = 0;
            AE_FILE_EVENT *fe = &event_loop->events[j];

            if (fe->mask == AE_NONE) continue;
            if (fe->mask & AE_READABLE && FD_ISSET(j,&state->_rfds))
                mask |= AE_READABLE;
            if (fe->mask & AE_WRITABLE && FD_ISSET(j,&state->_wfds))
                mask |= AE_WRITABLE;
            event_loop->fired[numevents].fd = j;
            event_loop->fired[numevents].mask = mask;
            numevents++;
        }
    }
    return numevents;
}

static char * api_name(void) {
    return "select";
}
