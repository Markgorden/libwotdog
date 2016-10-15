/* Background I/O service for ....
 *
 * This file implements operations that we need to perform in the background.
 * Currently there is only a single operation, that is a background close(2)
 * system call. This is needed as when the process is the last owner of a
 * reference to a file closing it means unlinking it, and the deletion of the
 * file is slow, blocking the server.
 *
 * DESIGN
 * ------
 *
 * The design is trivial, we have a structure representing a job to perform
 * and a different thread and job queue for every job type.
 * Every thread wait for new jobs in its queue, and process every job
 * sequentially.
 *
 * Jobs of the same type are guaranteed to be processed from the least
 * recently inserted to the most recently inserted (older jobs processed
 * first).
 *
 * Currently there is no way for the creator of the job to be notified about
 * the completion of the operation, this will only be added when/if needed.
 *
 */

#include "bio.h"

static pthread_t bio_threads[BIO_NUM_OPS];
static pthread_mutex_t bio_mutex[BIO_NUM_OPS];
static pthread_cond_t bio_condvar[BIO_NUM_OPS];
static list * bio_jobs[BIO_NUM_OPS];
static unsigned long long bio_pending[BIO_NUM_OPS];

struct bio_job 
{
    time_t time;
    void *arg1, *arg2, *arg3;
};

void * bio_process_background_jobs(void *arg);
#define BIO_THREAD_STACK_SIZE (1024*1024*4)
void bio_init(void) 
{
    pthread_attr_t attr;
    pthread_t thread;
    size_t stacksize;
    int j;
    for (j = 0; j < BIO_NUM_OPS; j++) 
	{
        pthread_mutex_init(&bio_mutex[j],NULL);
        pthread_cond_init(&bio_condvar[j],NULL);
        bio_jobs[j] = listCreate();
        bio_pending[j] = 0;
    }
    pthread_attr_init(&attr);
    pthread_attr_getstacksize(&attr,&stacksize);
    if (!stacksize) stacksize = 1; 
    while (stacksize < BIO_THREAD_STACK_SIZE) stacksize *= 2;
    pthread_attr_setstacksize(&attr, stacksize);
    for (j = 0; j < BIO_NUM_OPS; j++) 
	{
        void *arg = (void*)(unsigned long) j;
        if (pthread_create(&thread,&attr,bio_process_background_jobs,arg) != 0) 
		{
            //serverLog(LL_WARNING,"Fatal: Can't initialize Background Jobs.");
            exit(1);
        }
        bio_threads[j] = thread;
    }
}

void bio_create_background_job(int type, void *arg1, void *arg2, void *arg3) 
{
    struct bio_job *job = zmalloc(sizeof(*job));
    job->time = time(NULL);
    job->arg1 = arg1;
    job->arg2 = arg2;
    job->arg3 = arg3;
    pthread_mutex_lock(&bio_mutex[type]);
    listAddNodeTail(bio_jobs[type],job);
    bio_pending[type]++;
    pthread_cond_signal(&bio_condvar[type]);
    pthread_mutex_unlock(&bio_mutex[type]);
}

void *bio_process_background_jobs(void *arg) {
    struct bio_job *job;
    unsigned long type = (unsigned long) arg;
    sigset_t sigset;
    if (type >= BIO_NUM_OPS) {
        //serverLog(LL_WARNING,"Warning: bio thread started with wrong type %lu",type);
        return NULL;
    }
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_mutex_lock(&bio_mutex[type]);
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);
    if (pthread_sigmask(SIG_BLOCK, &sigset, NULL))
        ;//serverLog(LL_WARNING,"Warning: can't mask SIGALRM in bio.c thread: %s", strerror(errno));
    while(1) 
	{
        listNode *ln;
        if (listLength(bio_jobs[type]) == 0) 
		{
            pthread_cond_wait(&bio_condvar[type],&bio_mutex[type]);
            continue;
        }
        ln = listFirst(bio_jobs[type]);
        job = ln->value;
        pthread_mutex_unlock(&bio_mutex[type]);
        if (type == BIO_CLOSE_FILE) 
		{
            close((long)job->arg1);
        } 
		else if (type == BIO_AOF_FSYNC) 
		{
            ;//aof_fsync((long)job->arg1);
        }
		else 
		{
           ;// serverPanic("Wrong job type in bioProcessBackgroundJobs().");
        }
        zfree(job);
        pthread_mutex_lock(&bio_mutex[type]);
        listDelNode(bio_jobs[type],ln);
        bio_pending[type]--;
    }
}

unsigned long long bio_pending_jobs_of_type(int type) 
{
    unsigned long long val;
    pthread_mutex_lock(&bio_mutex[type]);
    val = bio_pending[type];
    pthread_mutex_unlock(&bio_mutex[type]);
    return val;
}

void bio_kill_threads(void) 
{
    int err, j;
    for (j = 0; j < BIO_NUM_OPS; j++) 
	{
        if (pthread_cancel(bio_threads[j]) == 0) 
		{
            if ((err = pthread_join(bio_threads[j],NULL)) != 0) 
			{
                ;//serverLog(LL_WARNING,"Bio thread for job type #%d can be joined: %s",j, strerror(err));
            } 
			else 
			{
                ;//serverLog(LL_WARNING,"Bio thread for job type #%d terminated",j);
            }
        }
    }
}


