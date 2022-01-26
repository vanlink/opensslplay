#include <stdio.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/async.h>

#include "sslcommon.h"

int jobfunc(void *arg)
{
    ASYNC_JOB *currjob;
    unsigned char *msg;
    int cnt = 0;

    currjob = ASYNC_get_current_job();
    if (currjob != NULL) {
        printf("======= Executing within a job\n");
    } else {
        printf("======= Not executing within a job - should not happen\n");
        return 0;
    }

    msg = (unsigned char *)arg;
    printf("======= Passed in message is: %s\n", msg);

    ASYNC_pause_job();
    printf("======= job %d\n", cnt++);

    ASYNC_pause_job();
    printf("======= job %d\n", cnt++);

    ASYNC_pause_job();
    printf("======= job %d\n", cnt++);

    return 1;
}

int main(void)
{
    ASYNC_JOB *job = NULL;
    ASYNC_WAIT_CTX *ctx = NULL;
    int ret;
    unsigned char msg[13] = "Hello world!";
    int cnt = 0;

    printf("Starting...\n");

    ctx = ASYNC_WAIT_CTX_new();
    if (ctx == NULL) {
        printf("Failed to create ASYNC_WAIT_CTX\n");
        abort();
    }

    for (;;) {
        switch (ASYNC_start_job(&job, ctx, &ret, jobfunc, msg, sizeof(msg))) {
        case ASYNC_ERR:
        case ASYNC_NO_JOBS:
            printf("An error occurred\n");
            goto end;
        case ASYNC_PAUSE:
            printf("Job was paused %d\n", cnt++);
            break;
        case ASYNC_FINISH:
            printf("Job finished with return value %d\n", ret);
            goto end;
        }
    }

end:
    ASYNC_WAIT_CTX_free(ctx);
    printf("Finishing\n");

    return 0;
}


