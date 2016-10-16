/*
 Authors: ZhangXuelian
 	


 Changes:
 	
	
*/
#include "libpthread.h"
#include "../libutility/libutility.h"

bool create_thread(THREAD_CONTEXT * c)
{
	bool ret = true;
	pthread_attr_t attr;
	struct sched_param param;
	
	c->exit = false;
	c->quited = false;
	c->tick = get_tickcount();
	
	if (c->priority < MIN_PRIORITY) c->priority = MIN_PRIORITY;
	if (c->priority > MAX_PRIORITY) c->priority = MAX_PRIORITY;
		
	pthread_attr_init(&attr);
	if (c->priority == 0)
	{
		pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
		param.sched_priority = sched_get_priority_max(SCHED_OTHER);
	}
	else
	{
		pthread_attr_setschedpolicy(&attr, SCHED_RR);
		param.sched_priority = c->priority;
	}
	pthread_attr_setschedparam(&attr, &param);
	if (pthread_create(&c->thread, &attr, c->handler, (void *)c))
		ret = false;
	
	pthread_attr_destroy(&attr);
	
	return ret;
}

/*void end_thread(THREAD_CONTEXT * c)
{
	c->exit = 1;
	pthread_join(c->thread, NULL);
}*/

bool is_thread_alive(THREAD_CONTEXT * c)
{
	unsigned long tick = c->tick;
	if (tick && 
		((long)(get_tickcount() - tick) > c->alive_threshold))
		return false;
	
	return true;
}


void set_thread_priority(int priority)
{
	struct sched_param param;
	int policy;

	if (priority < MIN_PRIORITY) priority = MIN_PRIORITY;
	if (priority > MAX_PRIORITY) priority = MAX_PRIORITY;

	if (priority == 0)
	{
		policy = SCHED_OTHER;
		param.sched_priority = sched_get_priority_max(SCHED_OTHER);
	}
	else
	{
		policy =  SCHED_RR;
		param.sched_priority = priority;
	}

	if (pthread_setschedparam(pthread_self(), policy, &param))
		printf("%s: failed\n", __func__);
}



