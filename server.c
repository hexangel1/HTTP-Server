#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <errno.h>
#include "server.h"
#include "template.h"
#include "userthread.h"
#include "http.h"
#include "tcp.h"

static volatile sig_atomic_t sig_event_flag = sigev_no_events;

static void signal_handler(int signum)
{
        if (signum == SIGCHLD)
                sig_event_flag = sigev_childexit;
        else if (signum == SIGUSR1 || signum == SIGHUP)
                sig_event_flag = sigev_restart;
        else if (signum == SIGUSR2 || signum == SIGTERM)
                sig_event_flag = sigev_terminate;
}

static void register_sigactions(void)
{
        struct sigaction sa;
        sa.sa_handler = SIG_IGN;
        sigfillset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGPIPE, &sa, NULL);
        sa.sa_handler = signal_handler;
        sigaction(SIGHUP, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGUSR1, &sa, NULL);
        sigaction(SIGUSR2, &sa, NULL);
        sa.sa_flags = SA_NOCLDSTOP;
        sigaction(SIGCHLD, &sa, NULL);
}

static void block_signals(sigset_t *origmask)
{
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGHUP);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGUSR1);
        sigaddset(&mask, SIGUSR2);
        sigaddset(&mask, SIGCHLD);
        sigprocmask(SIG_BLOCK, &mask, origmask);
}

static void die_server()
{
        kill(0, SIGKILL);
        _exit(1);
}

static void debug_log(struct http_server *serv, const char *fmt, ...)
{
        static char mesg_buff[512];
        va_list args;
        va_start(args, fmt);
        snprintf(mesg_buff, sizeof(mesg_buff), "worker[%d]: %s",
                 serv->wpd->worker_id, fmt);
        vfprintf(stderr, mesg_buff, args);
        va_end(args);
}

static int unlock_more_fds(unsigned int extra_fds_amount)
{
        int res;
        struct rlimit rlim;
        res = getrlimit(RLIMIT_NOFILE, &rlim);
        if (res == -1) {
                perror("getrlimit");
                return -1;
        }
        if (extra_fds_amount < RLIM_INFINITY - rlim.rlim_cur)
                rlim.rlim_cur += extra_fds_amount;
        else
                rlim.rlim_cur = RLIM_INFINITY;
        if (rlim.rlim_cur > rlim.rlim_max)
                rlim.rlim_cur = rlim.rlim_max;
        res = setrlimit(RLIMIT_NOFILE, &rlim);
        if (res == -1) {
                perror("setrlimit");
                return -1;
        }
        return 0;
}

static void poll_if_can_write(struct worker_process_data *wpd, int fd, void *ctx)
{
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.ptr = ctx;
        epoll_ctl(wpd->eventfd, EPOLL_CTL_MOD, fd, &ev);
}

static void start_poll_fd(struct worker_process_data *wpd, int fd, void *ctx)
{
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.ptr = ctx;
        epoll_ctl(wpd->eventfd, EPOLL_CTL_ADD, fd, &ev);
        wpd->sess_amount++;
}

static void stop_poll_fd(struct worker_process_data *wpd, int fd)
{
        struct epoll_event ev;
        ev.events = 0;
        ev.data.ptr = NULL;
        epoll_ctl(wpd->eventfd, EPOLL_CTL_DEL, fd, &ev);
        wpd->sess_amount--;
}

static struct session *create_session(int sockfd)
{
        struct session *ptr = malloc(sizeof(*ptr));
        ptr->socket_d = sockfd;
        ptr->control_fd[0] = -1;
        ptr->control_fd[1] = -1;
        ptr->defered_exit = 0;
        ptr->tx_fd = -1;
        ptr->tx_buf = NULL;
        ptr->buf_used = 0;
        ptr->sendbuf = make_buffer(OUTBUFSIZE);
        ptr->ipaddr = strdup(get_peer_ip(sockfd));
        ptr->port = get_peer_port(sockfd);
        ptr->first_handler = 1;
        ptr->state = st_request;
        ptr->userdata = make_safe_value(NULL, NULL);
        ptr->user_job = NULL;
        ptr->job_arg = NULL;
        ptr->job_ret = NULL;
        ptr->next_arg = NULL;
        ptr->callback = NULL;
        ptr->request = NULL;
        ptr->prev = NULL;
        ptr->next = NULL;
        return ptr;
}

static void delete_session(struct session *ptr)
{
        tcp_shutdown(ptr->socket_d);
        if (ptr->tx_fd != -1)
                close(ptr->tx_fd);
        if (ptr->tx_buf)
                free_buffer(ptr->tx_buf);
        free_safe_value(ptr->userdata);
        free_safe_value(ptr->job_arg);
        free_safe_value(ptr->job_ret);
        free_safe_value(ptr->next_arg);
        free_buffer(ptr->sendbuf);
        free(ptr->request);
        free(ptr->ipaddr);
        free(ptr);
}

static void exit_session(struct http_server *serv, struct session *ptr)
{
        if (ptr->state == st_waiting) {
                ptr->state = st_waitexit;
                ptr->defered_exit = 1;
                stop_poll_fd(serv->wpd, ptr->socket_d);
        } else {
                ptr->state = st_goodbye;
        }
}

static void add_session(struct http_server *serv, int sockfd)
{
        struct session *ctx;
        struct worker_process_data *wpd = serv->wpd;
        ctx = create_session(sockfd);
        ctx->prev = NULL;
        ctx->next = wpd->sess;
        if (wpd->sess)
            wpd->sess->prev = ctx;
        wpd->sess = ctx;
        start_poll_fd(wpd, ctx->socket_d, ctx);
        debug_log(serv, "connect from %s:%d\n", ctx->ipaddr, ctx->port);
}

static void remove_session(struct worker_process_data *wpd, struct session *ptr)
{
        if (!ptr->defered_exit)
                stop_poll_fd(wpd, ptr->socket_d);
        if (ptr->next)
                ptr->next->prev = ptr->prev;
        if (ptr->prev)
                ptr->prev->next = ptr->next;
        else
                wpd->sess = ptr->next;
        delete_session(ptr);
}

static void delete_all_sessions(struct session *sess)
{
        struct session *tmp;
        while (sess) {
                tmp = sess;
                sess = sess->next;
                delete_session(tmp);
        }
}

static void send_buffer(struct session *sess)
{
        struct data_buffer *dbuf = sess->sendbuf;
        http_crlf(sess);
        tcp_send(sess->socket_d, dbuf->data, dbuf->buf_used);
        dbuf->buf_used = 0;
}

static unsigned int get_handler_no(struct http_server *serv, const char *req_path)
{
        int i, slash_amount = 0, pathlen = 0;
        unsigned int handler_no = -1;
        char *path;
       
        for (i = 0; req_path[i]; ++i) {
                if (req_path[i] == '/')
                        ++slash_amount;
                else if (req_path[i] == '?')
                        break;
                ++pathlen;
        }
        if (pathlen == 0)
                return -1;

        path = malloc(pathlen + 2);
        memcpy(path, req_path, pathlen);
        if (path[pathlen - 1] != '/') {
                path[pathlen] = '/';
                ++slash_amount;
                ++pathlen;
        }
        path[pathlen] = 0;

        while (slash_amount > 0) {
                int handler_idx = tree_get(serv->root, path);
                if (handler_idx != -1) {
                        handler_no = handler_idx;
                        break;
                }
                --slash_amount;
                if (slash_amount > 0) {
                        for (i = pathlen - 2; i > 0 && path[i] != '/'; --i)
                                path[i] = 0;
                        pathlen = i + 1;
                }
        }
        free(path);
        return handler_no;
}

static void callback_post_func(struct http_server *serv, struct session *sess)
{
        free_safe_value(sess->job_arg);
        free_safe_value(sess->job_ret);
        sess->job_arg = sess->next_arg;
        sess->job_ret = NULL;
        sess->next_arg = NULL;
        if (sess->sendbuf->buf_used > 0)
                send_buffer(sess);
        if (sess->state == st_transfer)
                poll_if_can_write(serv->wpd, sess->socket_d, sess);
        else if (sess->state == st_waiting) {
                int res = user_thread_run(sess);
                if (res == -1) {
                        http_response(sess, status_internal_server_error);
                        send_buffer(sess);
                        sess->state = st_goodbye;
                } else {
                        start_poll_fd(serv->wpd, sess->control_fd[0], sess);
                }
        } else
                sess->state = st_goodbye;
}

static void handle_request(struct http_server *serv, struct session *sess)
{
        if (sess->first_handler) {
                int handler_idx = get_handler_no(serv, sess->request->path);
                if (handler_idx == -1) {
                        http_response(sess, status_not_found);
                        send_buffer(sess);
                } else {
                        sess->callback = serv->handlers[handler_idx];
                }
                sess->first_handler = 0;
        }
        if (sess->callback) {
                http_handler callback = sess->callback;
                sess->callback = NULL;
                callback(sess, sess->request);
                callback_post_func(serv, sess);
        } else {
                sess->state = st_goodbye;
        }
}

static int handle_thread_exit(struct http_server *serv, struct session *sess)
{
        char c;
        int res = read(sess->control_fd[0], &c, 1);
        if (res != 1)
                return 0;
        stop_poll_fd(serv->wpd, sess->control_fd[0]);
        close(sess->control_fd[0]);
        close(sess->control_fd[1]);
        sess->control_fd[0] = -1;
        sess->control_fd[1] = -1;
        sess->state = sess->state == st_waiting ? st_handle : st_goodbye;
        return 1;
}

static void receive_data(struct http_server *serv, struct session *ptr)
{
        int rc, busy = ptr->buf_used;
        if (ptr->state == st_waiting || ptr->state == st_waitexit) {
                int exited = handle_thread_exit(serv, ptr);
                if (exited)
                        return;
        }
        rc = tcp_recv(ptr->socket_d, ptr->buf + busy, INBUFSIZE - busy);
        if (rc <= 0) {
                exit_session(serv, ptr);
                return;
        }
        if (ptr->state != st_request)
                return;
        ptr->buf_used += rc;
        if (http_check_request_end(ptr->buf, ptr->buf_used)) {
                ptr->request = http_parse_request(ptr->buf, ptr->buf_used);
                ptr->state = st_handle;
        } else {
                if (ptr->buf_used >= INBUFSIZE)
                        exit_session(serv, ptr);
        }
}

static void send_data(struct http_server *serv, struct session *ptr)
{
        ssize_t wc;
        if (ptr->state != st_transfer)
                return;
        if (ptr->tx_fd != -1)
                wc = tcp_sendfile(ptr->socket_d, ptr->tx_fd, ptr->tx_len);
        else
                wc = tcp_send(ptr->socket_d, ptr->tx_buf->data + ptr->tx_wc, ptr->tx_len);
        if (wc <= 0)
                ptr->state = st_goodbye;
        ptr->tx_len -= wc;
        ptr->tx_wc += wc;
        if (ptr->tx_len <= 0)
                ptr->state = st_handle;
}

static struct worker_process_data *make_worker_data(int listen_sock, int id)
{
        struct worker_process_data *wpd;
        struct epoll_event ev;

        int evfd = epoll_create(1);
        if (evfd == -1) {
                perror("epoll_create");
                return NULL;
        }

        wpd = malloc(sizeof(*wpd));
        wpd->worker_id = id;
        wpd->eventfd = evfd;
        wpd->sess_amount = 0;
        wpd->sess = NULL;

        ev.events = EPOLLIN;
#ifdef USE_EXCLUSIVE
        ev.events |= EPOLLEXCLUSIVE;
#endif
        ev.data.ptr = NULL;
        epoll_ctl(wpd->eventfd, EPOLL_CTL_ADD, listen_sock, &ev);
        return wpd;
}

static struct master_process_data *make_master_data(int *pids, int len)
{
        struct master_process_data *mpd;
        mpd = malloc(sizeof(*mpd));
        mpd->worker_pids = malloc(len * sizeof(int));
        memcpy(mpd->worker_pids, pids, len * sizeof(int));
        return mpd;
}

static int create_workers(struct http_server *serv)
{
        int i, pid;
        int pids[WORKER_NUMBER_MAX];
        for (i = 1; i < serv->workers_amount; i++) {
                pid = fork();
                if (pid == -1) {
                        perror("fork");
                        die_server();
                }
                if (pid == 0) {
                        serv->wpd = make_worker_data(serv->listen_sock, i);
                        return 0;
                }
                pids[i] = pid;
        }
        pids[0] = getpid();
        serv->wpd = make_worker_data(serv->listen_sock, 0);
        serv->mpd = make_master_data(pids, serv->workers_amount);
        return 0;
}

static void terminate_server(struct http_server *serv)
{
        int i;
        if (!serv->mpd)
                return;
        for (i = 1; i < serv->workers_amount; ++i)
                kill(serv->mpd->worker_pids[i], SIGTERM);
        for (i = 1; i < serv->workers_amount; ++i)
                wait(NULL);
}

static void remove_zombies(struct http_server *serv)
{
        while ((waitpid(-1, NULL, WNOHANG)) > 0) {
                ;
        }
}

static int handle_signal_event(struct http_server *serv)
{
        enum signal_event event = sig_event_flag;
        sig_event_flag = sigev_no_events;
        switch (event) {
        case sigev_childexit:
                remove_zombies(serv);
                return 0;
        case sigev_restart:
                /*restart_server(serv);*/
                return 0;
        case sigev_terminate:
                terminate_server(serv);
                return 1;
        case sigev_no_events:
                ;
        }
        return 0;
}

static void accept_connection(struct http_server *serv)
{
        int sockfd = tcp_accept(serv->listen_sock);
        if (sockfd != -1) {
                tcp_nonblock_io(sockfd);
                add_session(serv, sockfd);
        }
}

void http_server_handle(struct http_server *serv)
{
        int i, nfds, res;
        struct epoll_event events[EVENT_MAX];
        for (;;) {
                nfds = epoll_pwait(serv->wpd->eventfd, events, EVENT_MAX,
                                   serv->timeout, &serv->sigmask);
                if (nfds == -1) {
                        if (errno != EINTR) {
                                perror("epoll_wait");
                                die_server();
                        }
                        res = handle_signal_event(serv);
                        if (res)
                                break;
                        continue;
                }
               
                for (i = 0; i < nfds; ++i) {
                        struct session *context = events[i].data.ptr;
                        if (context) {
                                if (events[i].events & EPOLLIN)
                                        receive_data(serv, context);
                                if (events[i].events & EPOLLOUT)
                                        send_data(serv, context);
                                if (context->state == st_handle)
                                        handle_request(serv, context);
                                if (context->state == st_goodbye)
                                        remove_session(serv->wpd, context);
                        } else {
                                if (events[i].events & EPOLLIN)
                                        accept_connection(serv);
                        }
                }
        }
}

int http_server_up(struct http_server *serv)
{
        int res;
        serv->workdir_fd = open(serv->workdir, O_RDONLY | O_DIRECTORY);
        if (serv->workdir_fd == -1)
                return -1;
        serv->listen_sock = tcp_create_socket(serv->ipaddr, serv->port);
        if (serv->listen_sock == -1)
                return -1;
        tcp_nonblock_io(serv->listen_sock);
        res = unlock_more_fds(EXTRA_FDS_AMOUNT);
        if (res == -1)
                return -1;
        register_sigactions();
        block_signals(&serv->sigmask);
        return create_workers(serv);
}

void http_server_down(struct http_server *serv)
{
        debug_log(serv, "terminating...\n");
        close(serv->wpd->eventfd);
        delete_all_sessions(serv->wpd->sess);
        if (serv->mpd)
                tcp_shutdown(serv->listen_sock);
        else
                close(serv->listen_sock);
        close(serv->workdir_fd);
        if (serv->mpd) {
                free(serv->mpd->worker_pids);
                free(serv->mpd);
        }
        tree_free(serv->root);
        free(serv->handlers);
        free(serv->wpd);
        free(serv->workdir);
        free(serv->ipaddr);
        free(serv);
}

void 
http_handle(struct http_server *serv, const char *path, http_handler handler)
{
        tree_set(&serv->root, path, serv->handlers_set);
        if (serv->handlers_set == serv->handlers_size) {
                serv->handlers_size <<= 1;
                serv->handlers = realloc(serv->handlers, sizeof(http_handler) * serv->handlers_size);
        }
        serv->handlers[serv->handlers_set] = handler;
        serv->handlers_set++;
}

void http_send_file(struct session *sess, int fd, size_t bytes)
{
        sess->tx_fd = fd;
        sess->tx_len = bytes;
        sess->tx_wc = 0;
        sess->state = st_transfer;
}

void http_send_buffer(struct session *sess, struct data_buffer *dbuf)
{
        sess->tx_buf = dbuf;
        sess->tx_len = dbuf->buf_used;
        sess->tx_wc = 0;
        sess->state = st_transfer;
}

void http_spawn_thread(struct session *sess, user_thread job, safe_value_t *arg)
{
        sess->user_job = job;
        sess->next_arg = arg;
        sess->state = st_waiting;
}

void http_set_userdata(struct session *sess, void *val, value_destructor del)
{
        rewrite_safe_value(sess->userdata, val, del);
}

void *http_get_userdata(struct session *sess)
{
        return get_safe_value(sess->userdata);
}

void *http_pick_userdata(struct session *sess)
{
        return pick_safe_value(sess->userdata);
}

void *http_get_arg(struct session *sess)
{
        if (!sess->job_arg)
                return NULL;
        return get_safe_value(sess->job_arg);
}

void *http_get_ret(struct session *sess)
{
        if (!sess->job_ret)
                return NULL;
        return get_safe_value(sess->job_ret);
}

void *http_pick_arg(struct session *sess)
{
        if (!sess->job_arg)
                return NULL;
        return pick_safe_value(sess->job_arg);
}

void *http_pick_ret(struct session *sess)
{
        if (!sess->job_ret)
                return NULL;
        return pick_safe_value(sess->job_ret);
}

void http_set_callback(struct session *sess, http_handler func)
{
        sess->callback = func;
}

struct http_server *new_http_server(const char *ipaddr, unsigned short port,
                                    const char *workdir, int workers_amount)
{
        struct http_server *serv = malloc(sizeof(*serv));
        serv->listen_sock = -1;
        serv->workers_amount = workers_amount;
        serv->timeout = -1;
        serv->workdir = strdup(workdir);
        serv->ipaddr = strdup(ipaddr);
        serv->port = port;
        serv->handlers_set = 0;
        serv->handlers_size = 16;
        serv->handlers = malloc(sizeof(http_handler) * serv->handlers_size);
        serv->root = NULL;
        sigemptyset(&serv->sigmask);
        serv->mpd = NULL;
        serv->wpd = NULL;
        return serv;
}

