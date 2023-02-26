#ifndef SERVER_H_SENTRY
#define SERVER_H_SENTRY

#include <sys/types.h>
#include <pthread.h>

#define INBUFSIZE 1024
#define OUTBUFSIZE 4096
#define EXTRA_FDS_AMOUNT 4000

enum signal_event {
        sigev_no_events,
        sigev_restart,
        sigev_terminate
};

enum fsm_state {
        st_request,
        st_process,
        st_sendbuf,
        st_goodbye
};

struct session {
        int fds_idx;
        int socket_d;
        int tx_fd;
        char *tx_buf;
        size_t tx_len;
        size_t tx_wc;
        int buf_used;
        int sbuf_used;
        char buf[INBUFSIZE];
        char sendbuf[OUTBUFSIZE];
        char *ipaddr;
        unsigned short port;
        enum fsm_state state;
        struct http_request *request;
        struct session *next;
};

struct worker_task {
        int sockfd;
};

struct shared_worker_data {
        pthread_mutex_t mutex;
        int *requests_per_worker;
};

struct http_server {
        int workdir_fd;
        int listen_sock;
        int workers_amount;
        char *ipaddr;
        char *workdir;
        unsigned short port;
        int *worker_fds;
        pthread_t *thread_ids;
        struct shared_worker_data *swd;
};

struct service_worker {
        int worker_id;
        int workdir_fd;
        struct session *sess;
        struct pollfd *fds;
        int nfds;
        int timeout;
        int has_finished;
        struct shared_worker_data *swd;
};

/* handles signals, listening socket and client connections */
void http_server_handle(struct http_server *serv);

/* starts http server */
int http_server_up(struct http_server *serv);

/* stops http server */
void http_server_down(struct http_server *serv);

/* creates new http server */
struct http_server *new_http_server(const char *ipaddr, unsigned short port,
                                    const char *workdir, int workers_amount);

#endif

