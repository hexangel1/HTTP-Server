#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include "server.h"
#include "template.h"
#include "http.h"
#include "tcp.h"

static volatile sig_atomic_t sig_event_flag = sigev_no_events;

static void signal_handler(int signum)
{
        if (signum == SIGUSR1 || signum == SIGHUP)
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
}

static void block_signals(void)
{
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGHUP);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGUSR1);
        sigaddset(&mask, SIGUSR2);
        pthread_sigmask(SIG_BLOCK, &mask, NULL);
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

static void poll_if_can_write(struct service_worker *serv, int idx)
{
        serv->fds[idx].events |= POLLOUT;
}

static void stop_poll_fd(struct service_worker *serv, int idx)
{
        serv->fds[idx].fd = -1;
        serv->fds[idx].events = 0;
        serv->fds[idx].revents = 0;
}

static int start_poll_fd(struct service_worker *serv, int sockfd)
{
        int old_size, i;
        for (i = 0; i < serv->nfds; i++) {
                if (serv->fds[i].fd == -1) {
                        serv->fds[i].fd = sockfd;
                        serv->fds[i].events = POLLIN;
                        return i;
                }
        }
        old_size = serv->nfds;
        serv->nfds = old_size ? old_size << 1 : 4;
        serv->fds = realloc(serv->fds, serv->nfds * sizeof(*serv->fds));
        for (i = old_size; i < serv->nfds; i++)
                stop_poll_fd(serv, i);
        serv->fds[old_size].fd = sockfd;
        serv->fds[old_size].events = POLLIN;
        return old_size;
}

static void distribute_task(struct http_server *serv, int sockfd)
{
        int i, min, id = 0;
        struct worker_task task;
        task.sockfd = sockfd;
        /* crit section begin */
        pthread_mutex_lock(&serv->swd->mutex);
        min = serv->swd->requests_per_worker[0];
        for (i = 1; i < serv->workers_amount; i++) {
                if (serv->swd->requests_per_worker[i] < min) {
                        min = serv->swd->requests_per_worker[i];
                        id = i;
                }
        }
        serv->swd->requests_per_worker[id]++;
        pthread_mutex_unlock(&serv->swd->mutex);
        /* crit section end */
        write(serv->worker_fds[id], &task, sizeof(task));
}

static struct session *create_session(int idx, int sockfd)
{
        struct session *ptr = malloc(sizeof(*ptr));
        ptr->fds_idx = idx;
        ptr->socket_d = sockfd;
        ptr->tx_fd = -1;
        ptr->tx_buf = NULL;
        ptr->buf_used = 0;
        ptr->sbuf_used = 0;
        ptr->ipaddr = strdup(get_peer_ip(sockfd));
        ptr->port = get_peer_port(sockfd);
        ptr->state = st_request;
        ptr->request = NULL;
        ptr->next = NULL;
        return ptr;
}

static void delete_session(struct session *ptr)
{
        tcp_shutdown(ptr->socket_d);
        if (ptr->tx_fd != -1)
                close(ptr->tx_fd);
        free(ptr->request);
        free(ptr->ipaddr);
        free(ptr->tx_buf);
        free(ptr);
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

static void delete_finished_sessions(struct service_worker *serv)
{
        struct session **sess = &serv->sess;
        while (*sess) {
                if ((*sess)->state == st_goodbye) {
                        struct session *tmp = *sess;
                        *sess = (*sess)->next;
                        stop_poll_fd(serv, tmp->fds_idx);
                        pthread_mutex_lock(&serv->swd->mutex);
                        serv->swd->requests_per_worker[serv->worker_id]--;
                        pthread_mutex_unlock(&serv->swd->mutex);
                        delete_session(tmp);
                } else {
                        sess = &(*sess)->next;
                }
        }
}

static void send_buffer(struct session *sess)
{
        tcp_send(sess->socket_d, sess->sendbuf, sess->sbuf_used);
        sess->sbuf_used = 0;
}

static void handle_request(struct service_worker *serv, struct session *sess)
{
        int res, fd;
        char path[512];
        const char *type;
        struct stat st_buf;
        snprintf(path, sizeof(path), ".%s", sess->request->path);
        fd = openat(serv->workdir_fd, path, O_RDONLY);
        if (fd == -1) {
                perror(path);
                http_response(sess, status_not_found);
                sess->state = st_goodbye;
                return;
        }
        res = fstat(fd, &st_buf);
        if (res == -1) {
                perror("fstat");
                http_response(sess, status_internal_server_error);
                sess->state = st_goodbye;
                close(fd);
                return;
        }
        if (S_ISDIR(st_buf.st_mode)) {
                generate_index_page(sess, sess->request->path, fd);
                close(fd);
                type = "text/html";
                sess->tx_wc = 0;
                sess->state = st_sendbuf;
        } else {
                sess->tx_fd = fd;
                sess->tx_len = st_buf.st_size;
                sess->tx_wc = 0;
                type = "binary";
                sess->state = st_process;
        }
        http_response(sess, status_ok);
        http_content_headers(sess, type, sess->tx_len, st_buf.st_mtime);
        http_crlf(sess);
        send_buffer(sess);
        poll_if_can_write(serv, sess->fds_idx);
}

static void receive_data(struct service_worker *serv, struct session *ptr)
{
        int rc, busy = ptr->buf_used;
        rc = tcp_recv(ptr->socket_d, ptr->buf + busy, INBUFSIZE - busy);
        if (rc <= 0) {
                serv->has_finished = 1;
                ptr->state = st_goodbye;
                return;
        }
        if (ptr->state == st_process)
                return;
        ptr->buf_used += rc;
        if (http_check_request_end(ptr->buf, ptr->buf_used)) {
                ptr->state = st_process;
                ptr->request = http_parse_request(ptr->buf, ptr->buf_used);
                handle_request(serv, ptr);
        } else {
                if (ptr->buf_used >= INBUFSIZE)
                        ptr->state = st_goodbye;
        }
}

static void send_data(struct service_worker *serv, struct session *ptr)
{
        ssize_t wc;
        if (ptr->state == st_process)
                wc = tcp_sendfile(ptr->socket_d, ptr->tx_fd, ptr->tx_len);
        else
                wc = tcp_send(ptr->socket_d, ptr->tx_buf + ptr->tx_wc, ptr->tx_len);
        if (wc <= 0) {
                serv->has_finished = 1;
                ptr->state = st_goodbye;
        }
        ptr->tx_len -= wc;
        ptr->tx_wc += wc;
        if (ptr->tx_len <= 0) {
                ptr->state = st_goodbye;
                serv->has_finished = 1;
        }
}

static void worker_terminate(struct service_worker *serv)
{
        fprintf(stderr, "worker[%d]: terminating...\n", serv->worker_id);
        close(serv->fds[0].fd);
        delete_all_sessions(serv->sess);
        free(serv->fds);
        free(serv);
}

static void read_control_channel(struct service_worker *serv)
{
        int idx;
        struct session *tmp;
        struct worker_task task;
        read(serv->fds[0].fd, &task, sizeof(task));
/*        fprintf(stderr, "Worker[%d]: get task %d\n",
                        serv->worker_id, task.sockfd);*/
        idx = start_poll_fd(serv, task.sockfd);
        tmp = create_session(idx, task.sockfd);
        tmp->next = serv->sess;
        serv->sess = tmp;
/*        fprintf(stderr, "connection from %s:%d\n", tmp->ipaddr, tmp->port);*/
}

static void *worker_thread(void *data)
{
        struct service_worker *w = (struct service_worker *)data;
        struct session *tmp;
        int res;
        block_signals();
        for (;;) {
                res = poll(w->fds, w->nfds, w->timeout);
                if (res == -1) {
                        perror("poll");
                        abort();
                }
                if (w->fds[0].revents & POLLHUP) {
                        worker_terminate(w);
                        break;
                }
                if (w->fds[0].revents & POLLIN) {
                        read_control_channel(w);
                        w->fds[0].revents = 0;
                }
                for (tmp = w->sess; tmp; tmp = tmp->next) {
                        if (w->fds[tmp->fds_idx].revents & POLLIN)
                                receive_data(w, tmp);
                        if (w->fds[tmp->fds_idx].revents & POLLOUT)
                                send_data(w, tmp);
                        w->fds[tmp->fds_idx].revents = 0;
                }
                if (w->has_finished) {
                        delete_finished_sessions(w);
                        w->has_finished = 0;
                }
        }
        pthread_exit(NULL);
}

static struct service_worker *make_worker(struct http_server *serv, int id)
{
        int fd[2];
        struct service_worker *sw = malloc(sizeof(*sw));
        sw->worker_id = id;
        sw->workdir_fd = serv->workdir_fd;
        sw->sess = NULL;
        sw->fds = NULL;
        sw->nfds = 0;
        sw->timeout = -1;
        sw->has_finished = 0;
        sw->swd = serv->swd;
        pipe(fd);
        start_poll_fd(sw, fd[0]);
        serv->worker_fds[id] = fd[1];
        return sw;
}

static void create_workers(struct http_server *serv)
{
        int i, res;
        struct service_worker *w;
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        for (i = 0; i < serv->workers_amount; i++) {
                w = make_worker(serv, i);
                res = pthread_create(&tid, &attr, worker_thread, w);
                if (res != 0) {
                        perror("pthread_create");
                        exit(EXIT_FAILURE);
                }
                serv->thread_ids[i] = tid;
        }
        pthread_attr_destroy(&attr);
}

static void stop_workers(struct http_server *serv)
{
        int i;
        for (i = 0; i < serv->workers_amount; i++) {
                close(serv->worker_fds[i]);
                pthread_join(serv->thread_ids[i], NULL);
        }
        pthread_mutex_destroy(&serv->swd->mutex);
}

static int handle_signal_event(struct http_server *serv)
{
        enum signal_event event = sig_event_flag;
        sig_event_flag = sigev_no_events;
        switch (event) {
        case sigev_restart:
                /*restart_server(serv);*/
                return 0;
        case sigev_terminate:
                fprintf(stderr, "Main: terminate\n");
                return 1;
        case sigev_no_events:
                ;
        }
        return 0;
}

void http_server_handle(struct http_server *serv)
{
        int sockfd, res;
        for (;;) {
                sockfd = tcp_accept(serv->listen_sock);
                if (sockfd == -1) {
                        if (errno != EINTR)
                                continue;
                        res = handle_signal_event(serv);
                        if (res)
                                break;
                } else {
                        tcp_nonblock_io(sockfd);
                        distribute_task(serv, sockfd);
                }
        }
}

int http_server_up(struct http_server *serv)
{
        int res;
        res = open(serv->workdir, O_RDONLY | O_DIRECTORY);
        if (res == -1)
                return -1;
        serv->workdir_fd = res;
        res = tcp_create_socket(serv->ipaddr, serv->port);
        if (res == -1)
                return -1;
        serv->listen_sock = res;
        register_sigactions();
        res = unlock_more_fds(EXTRA_FDS_AMOUNT);
        if (res == -1)
                return -1;
        create_workers(serv);
        return 0;
}

void http_server_down(struct http_server *serv)
{
        tcp_shutdown(serv->listen_sock);
        stop_workers(serv);
        close(serv->workdir_fd);
        free(serv->worker_fds);
        free(serv->thread_ids);
        free(serv->swd->requests_per_worker);
        free(serv->swd);
        free(serv->workdir);
        free(serv->ipaddr);
        free(serv);
}

struct http_server *new_http_server(const char *ipaddr, unsigned short port,
                                    const char *workdir, int workers_amount)
{
        int i;
        struct http_server *serv = malloc(sizeof(*serv));
        serv->listen_sock = -1;
        serv->workers_amount = workers_amount;
        serv->ipaddr = strdup(ipaddr);
        serv->workdir = strdup(workdir);
        serv->port = port;
        serv->worker_fds = malloc(sizeof(int) * serv->workers_amount);
        for (i = 0; i < serv->workers_amount; i++)
                serv->worker_fds[i] = -1;
        serv->thread_ids = malloc(sizeof(pthread_t) * serv->workers_amount);
        serv->swd = malloc(sizeof(*serv->swd));
        pthread_mutex_init(&serv->swd->mutex, NULL);
        serv->swd->requests_per_worker = malloc(sizeof(int) *
                                                serv->workers_amount);
        for (i = 0; i < serv->workers_amount; i++)
                serv->swd->requests_per_worker[i] = 0;
        return serv;
}

