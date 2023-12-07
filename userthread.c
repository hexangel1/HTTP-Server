#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "server.h"
#include "userthread.h"

static void *thread_runner(void *data)
{
        struct session *sess = data;
        fprintf(stderr, "thread started\n");
        sess->user_thread(sess);
        sess->user_thread = NULL;
        fprintf(stderr, "thread finished\n");
        write(sess->control_fd[1], "", 1);
        pthread_exit(NULL);
}

int user_thread_run(struct session *sess)
{
        int res;
        pthread_t tid;
        pthread_attr_t attr;
        if (!sess->user_thread)
                return -1;
        res = pipe2(sess->control_fd, O_NONBLOCK);
        if (res == -1) {
                perror("pipe");
                return -1;
        }
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        res = pthread_create(&tid, &attr, thread_runner, sess);
        if (res != 0) {
                perror("pthread_create");
                return -1;
        }
        pthread_attr_destroy(&attr);
        return 0;
}
