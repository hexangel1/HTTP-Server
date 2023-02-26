#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include "server.h"

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

static void write_log(const char *message)
{
        if (daemon_state)
                syslog(LOG_INFO, "%s", message);
        fprintf(stderr, "%s\n", message);
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

static const char usage[] = "Usage: httpserv "
                            "[-d] [-w workers] [-i ipaddr] [-p port]\n";

int main(int argc, char **argv)
{
        int res;
        struct http_server *serv;
        res = get_command_line_options(argc, argv);
        if (res == -1) {
                fputs(usage, stderr);
                exit(EXIT_FAILURE);
        }
        if (daemon_state)
                daemonize();
        serv = new_http_server(ipaddr, port, workdir, workers_amount);
        res = http_server_up(serv);
        if (res == -1) {
                write_log("Failed to bring server up");
                exit(EXIT_FAILURE);
        }
        write_log("Running...");
        http_server_handle(serv);
        http_server_down(serv);
        write_log("Gracefully stopped");
        return 0;
}

