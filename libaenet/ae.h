/* A simple event-driven programming library. 
 * Originally I wrote this code for the Jim's event-loop 
 * (Jim is a Tcl interpreter) but later translated it in form of a library for easy reuse.
 *
 */

#ifndef __AE_H__
#define __AE_H__

#include <time.h>

#define AE_OK 0
#define AE_ERR -1

#define AE_NONE 0
#define AE_READABLE 1
#define AE_WRITABLE 2

#define AE_FILE_EVENTS 1
#define AE_TIME_EVENTS 2
#define AE_ALL_EVENTS (AE_FILE_EVENTS|AE_TIME_EVENTS)
#define AE_DONT_WAIT 4

#define AE_NOMORE -1
#define AE_DELETED_EVENT_ID -1

#define NOTUSED(V) ((void) V)

struct AE_EVENT_LOOP;

typedef void AeFileProc(struct AE_EVENT_LOOP * event_loop, int fd, void *client_data, int mask);
typedef int AeTimeProc(struct AE_EVENT_LOOP * event_loop, long long id, void *client_data);
typedef void AeEventFinalizerProc(struct AE_EVENT_LOOP * event_loop, void *client_data);
typedef void AeBeforeSleepProc(struct AE_EVENT_LOOP * event_loop);

typedef struct __tag_AeFile_Event {
    int mask; // one of AE_(READABLE|WRITABLE) 
    AeFileProc * rfile_proc;
    AeFileProc * wfile_proc;
    void * client_data;
} AE_FILE_EVENT;

typedef struct __tag_AeTimeEvent 
{
    long long id; 
    long when_sec; 
    long when_ms; 
    AeTimeProc *time_proc;
    AeEventFinalizerProc * finalizer_proc;
    void *client_data;
    struct AE_TIME_EVENT * next;
} AE_TIME_EVENT;


typedef struct __tag_Ae_Fired_Event 
{
    int fd;
    int mask;
} AE_FIRE_EVENT;

typedef struct __tag_Event_Loop 
{
    int max_fd;   
    int set_size; 
    long long time_event_next_id;
    time_t last_time;
    AE_FILE_EVENT * events; 
    AE_FIRE_EVENT * fired; 
    AE_TIME_EVENT * time_event_head;
    int stop;
    void * api_data; 
    AeBeforeSleepProc * before_sleep;
} AE_EVENT_LOOP;

int ae_wait(int fd, int mask, long long milliseconds);
void ae_main(AE_EVENT_LOOP * event_loop);
void ae_stop(AE_EVENT_LOOP * event_loop);
char * ae_get_api_name(void);

AE_EVENT_LOOP * ae_create_event_loop(int set_size);
void ae_delete_event_loop(AE_EVENT_LOOP * event_loop);
int ae_create_file_event(AE_EVENT_LOOP * event_loop, int fd, int mask, AeFileProc *proc, void *client_data);
void ae_delete_file_event(AE_EVENT_LOOP * event_loop, int fd, int mask);
int ae_get_file_events(AE_EVENT_LOOP * event_loop, int fd);
long long ae_create_time_event(AE_EVENT_LOOP * event_loop, long long milliseconds, AeTimeProc *proc, void *client_data, AeEventFinalizerProc *finalizer_proc);
int ae_delete_time_event(AE_EVENT_LOOP * event_loop, long long id);
int ae_process_events(AE_EVENT_LOOP * event_loop, int flags);
void ae_set_before_sleep_proc(AE_EVENT_LOOP * event_loop, AeBeforeSleepProc * before_sleep);
int ae_get_set_size(AE_EVENT_LOOP * event_loop);
int ae_resize_set_size(AE_EVENT_LOOP * event_loop, int set_size);

#endif
