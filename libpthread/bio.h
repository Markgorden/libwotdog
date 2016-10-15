/*
 */
 
 #include "libstl.h"
 
void bio_init(void);
void bio_create_background_job(int type, void *arg1, void *arg2, void *arg3);
unsigned long long bio_pending_jobs_of_type(int type);
void bio_wait_pending_jobs_le(int type, unsigned long long num);
time_t bio_older_job_of_type(int type);
void bio_kill_threads(void);

#define BIO_CLOSE_FILE    0 
#define BIO_AOF_FSYNC     1 
#define BIO_NUM_OPS       2

