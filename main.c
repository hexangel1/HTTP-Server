#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include "server.h"
#include "http.h"
#include "template.h"

static int daemon_state = 0;
static int workers_amount = 8;
static unsigned short port = 8080;
static const char *ipaddr = "127.0.0.1";
static const char *workdir = ".";

static void daemonize(void)
{
        int res, fd, fd_max = 1024;
        struct rlimit rl;
        res = getrlimit(RLIMIT_NOFILE, &rl);
        if (!res && rl.rlim_max != RLIM_INFINITY)
                fd_max = rl.rlim_cur;
        for (fd = 0; fd < fd_max; fd++)
                close(fd);
        open("/dev/null", O_RDWR);
        dup(0);
        dup(0);
        umask(0);
        chdir("/");
        if (fork() > 0)
                exit(0);
        setsid();
        if (fork() > 0)
                exit(0);
        openlog("httpservd", LOG_CONS | LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "Daemon started, pid == %d", getpid());
        atexit(&closelog);
}

static void write_log(const char *message, ...)
{
        static char mesg_buff[512];
        va_list args;
        va_start(args, message);
        vsnprintf(mesg_buff, sizeof(mesg_buff), message, args);
        if (daemon_state)
                syslog(LOG_INFO, "%s", mesg_buff);
        fprintf(stderr, "%s\n", mesg_buff);
        va_end(args);
}

static int get_command_line_options(int argc, char **argv)
{
        int opt, retval = 0;
        while ((opt = getopt(argc, argv, ":hdw:a:i:p:")) != -1) {
                switch (opt) {
                case 'h':
                        retval = -1;
                        break;
                case 'd':
                        daemon_state = 1;
                        break;
                case 'w':
                        workers_amount = atoi(optarg);
                        break;
                case 'a':
                        workdir = optarg;
                        break;
                case 'i':
                        ipaddr = optarg;
                        break;
                case 'p':
                        port = atoi(optarg);
                        break;
                case ':':
                        fprintf(stderr, "Opt -%c require an operand\n", optopt);
                        retval = -1;
                        break;
                case '?':
                        fprintf(stderr, "Unrecognized option: -%c\n", optopt);
                        retval = -1;
                        break;
                }
        }
        return retval;
}

static void my_handler(struct session *sess)
{
        fprintf(stderr, "Hello, World!\n");
        http_response(sess, status_internal_server_error);
}

static void my_callback(struct session *sess)
{
        struct data_buffer *dbuf;
        dbuf = http_get_userdata(sess);
        http_set_userdata(sess, NULL);
        http_send_buffer(sess, dbuf);
        http_response(sess, status_ok);
        http_content_headers(sess, "text/html", sess->tx_len, time(NULL));
}

static void my_thread(struct session *sess)
{       
        struct data_buffer *dbuf;
        int *fdptr = http_get_userdata(sess);
        dbuf = generate_index_page(sess->request->path, *fdptr);
        close(*fdptr);
        free(fdptr);
        http_set_userdata(sess, dbuf);
        http_set_callback(sess, my_callback);
        sleep(10);
}

static void my_handler2(struct session *sess)
{
        int res, fd;
        char path[512];
        struct stat st_buf;
        snprintf(path, sizeof(path), ".%s", sess->request->path);
        fd = open(path, O_RDONLY);
        if (fd == -1) {
                perror(path);
                http_response(sess, status_not_found);
                return;
        }
        res = fstat(fd, &st_buf);
        if (res == -1) {
                perror("fstat");
                http_response(sess, status_internal_server_error);
                close(fd);
                return;
        }
        if (S_ISDIR(st_buf.st_mode)) {
                int *ptr = malloc(sizeof(int));
                *ptr = fd;
                http_set_userdata(sess, ptr);
                http_spawn_thread(sess, my_thread);
        } else {
                http_response(sess, status_ok);
                http_content_headers(sess, "binary", st_buf.st_size, st_buf.st_mtime);
                http_send_file(sess, fd, st_buf.st_size);
        }
}

static void init_handers(struct http_server *serv)
{
        http_handle(serv, "/api/", my_handler);
        http_handle(serv, "/", my_handler2);
}

static const char usage[] = "Usage: httpserv "
                            "[-d] [-w workers] [-i ipaddr] [-p port]\n";

int main(int argc, char **argv)
{
        int res, is_master = 0;
        struct http_server *serv;
        res = get_command_line_options(argc, argv);
        if (res == -1) {
                fputs(usage, stderr);
                exit(EXIT_FAILURE);
        }
        if (daemon_state)
                daemonize();
        serv = new_http_server(ipaddr, port, workdir, workers_amount);
        init_handers(serv);

        res = http_server_up(serv);
        if (res == -1) {
                write_log("Failed to bring server up");
                exit(EXIT_FAILURE);
        }
        is_master = serv->mpd ? 1 : 0;
        if (is_master)
                write_log("[%d] Running...", getpid());
        http_server_handle(serv);
        http_server_down(serv);
        if (is_master)
                write_log("Gracefully stopped");
        return 0;
}

