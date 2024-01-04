#ifndef SERVER_H_SENTRY
#define SERVER_H_SENTRY

#include <signal.h>
#include "http.h"
#include "tree.h"
#include "buffer.h"
#include "array.h"

#define EVENT_MAX 1024
#define INBUFSIZE 4096
#define OUTBUFSIZE 4096
#define EXTRA_FDS_AMOUNT 4000
#define WORKER_NUMBER_MAX 1024

enum signal_event {
        sigev_no_events,
        sigev_childexit,
        sigev_restart,
        sigev_terminate
};

enum fsm_state {
        st_request,
        st_readbody,
        st_handle,
        st_transfer,
        st_waiting,
        st_waitexit,
        st_goodbye
};

struct session;
typedef void (*http_handler)(struct session *, struct http_request *request);
typedef safe_value_t *(*user_thread)(safe_value_t *arg, struct http_request *request);

struct session {
        int socket_d;
        int control_fd[2];
        int defered_exit;
        int tx_fd;
        struct data_buffer *tx_buf;
        size_t tx_len;
        size_t tx_wc;
        int buf_used;
        char buf[INBUFSIZE];
        struct data_buffer *sendbuf;
        char *ipaddr;
        unsigned short port;
        int first_handler;
        enum fsm_state state;
        http_handler callback;
        user_thread user_job;
        safe_value_t *job_arg;
        safe_value_t *job_ret;
        safe_value_t *userdata;
        safe_value_t *next_arg;
        struct http_request *request;
        struct session *prev;
        struct session *next;
};

struct master_process_data {
        int *worker_pids;
};

struct worker_process_data {
        int worker_id;
        int eventfd;
        int sess_amount;
        struct session *sess;
};

DECLARE_ARRAY_OF(handlers_disposition, http_handler);

struct http_server {
        int workdir_fd;
        int listen_sock;
        int workers_amount;
        int timeout;
        char *workdir;
        char *ipaddr;
        unsigned short port;
        sigset_t sigmask;
        handlers_disposition handlers;
        struct tree_node *root;
        struct master_process_data *mpd;
        struct worker_process_data *wpd;
};

/* handles signals, listening socket and client connections */
void http_server_handle(struct http_server *serv);

/* starts http server */
int http_server_up(struct http_server *serv);

/* stops http server */
void http_server_down(struct http_server *serv);

/* set handler for specified path */
void http_handle(struct http_server *serv, const char *path,
                 http_handler handler);

void http_send_file(struct session *sess, int fd, size_t bytes);

void http_send_buffer(struct session *sess, struct data_buffer *dbuf);
void http_spawn_thread(struct session *sess, user_thread job, safe_value_t *arg);

void http_set_userdata(struct session *sess, void *val, value_destructor del);
void *http_get_userdata(struct session *sess);
void *http_pick_userdata(struct session *sess);

void *http_get_arg(struct session *sess);
void *http_get_ret(struct session *sess);
void *http_pick_arg(struct session *sess);
void *http_pick_ret(struct session *sess);

void http_set_callback(struct session *sess, http_handler func);

/* creates new http server */
struct http_server *new_http_server(const char *ipaddr, unsigned short port,
                                    const char *workdir, int workers_amount);

#endif

