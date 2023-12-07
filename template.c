#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include "template.h"
#include "server.h"
#include "http.h"

#define TX_BUF_SIZE (1 << 16)

static const char *get_format_data(time_t tm)
{
        static char buff[64];
        strftime(buff, sizeof(buff), "%Y-%m-%d %H:%M", gmtime(&tm));
        return buff;
}

struct data_buffer *generate_index_page(const char *path, int dir_fd)
{
/*
const char *fmt1 = "<!DOCTYPE html>\n"
                           "<html>\n"
                           "<head><title>Index</title></head>\n"
                           "<body style=\"font-size:18px;\" bgcolor=\"gray\">\n"
                           "<h1>Index of %s</h1><hr><pre><a href=\"../\">../</a>\n";
        const char *fmt2 = "<a href=\"%s%s\">%s</a>   %s  %ld\n";
        const char *fmt3 = "</pre><hr></body>\n"
                           "</html>\n";
*/
        const char *fmt0 = {
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head><meta http-equiv=\"content-type\" "
        "content=\"text/html; charset=utf-8\"><meta name=\"viewport\" "
        "content=\"width=device-width\">\n"
        };
        const char *fmt1 = {
        "<style type=\"text/css\">body,html\n"
        "{background:#fff;font-family:\"Bitstream Vera Sans\","
        "\"Lucida Grande\",\"Lucida Sans Unicode\",Lucidux,Verdana,Lucida,"
        "sans-serif;}"
        "tr:nth-child(even) {background:#f4f4f4;}th,td {padding:0.1em 0.5em;}"
        "th {text-align:left;font-weight:bold;background:#eee;"
        "border-bottom:1px solid #aaa;}#list {border:1px solid #aaa;"
        "width:100%;}a {color:#a33;}a:hover {color:#e33;}\n"
        "</style>\n"
        };
        const char *fmt2 = {
        "<title>Index of %s</title>\n"
        "</head>\n"
        "<body><h1>Index of %s</h1>\n"
        };
        const char *fmt3 = {
        "<table id=\"list\"><thead><tr><th style=\"width:55%\"><a href=\"?C=N&amp;O=A\">File Name</a>&nbsp;<a href=\"?C=N&amp;O=D\">&nbsp;&darr;&nbsp;</a></th><th style=\"width:20%\"><a href=\"?C=S&amp;O=A\">File Size</a>&nbsp;<a href=\"?C=S&amp;O=D\">&nbsp;&darr;&nbsp;</a></th><th style=\"width:25%\"><a href=\"?C=M&amp;O=A\">Date</a>&nbsp;<a href=\"?C=M&amp;O=D\">&nbsp;&darr;&nbsp;</a></th></tr></thead>\n"
        };
        const char *fmt4 = {
        "<tr>"
        "<td class=\"link\"><a href=\"%s%s\" title=\"%s\">%s%s</a></td>"
        "<td class=\"size\">%ld</td>"
        "<td class=\"date\">%s</td>"
        "</tr>\n"
        };
        DIR *dirp;
        struct dirent *dent;
        struct stat st_buf;
        struct data_buffer *dbuf;
        int res;
        dirp = fdopendir(dir_fd);
        if (!dirp) {
                perror("fdopendir");
                return NULL;
        }
        res = fstat(dir_fd, &st_buf);
        if (res == -1) {
                perror("fstat");
                return NULL;
        }
        dbuf = make_buffer(TX_BUF_SIZE);
        write_buf_format(dbuf, fmt0);
        write_buf_format(dbuf, fmt1);
        write_buf_format(dbuf, fmt2, path, path);
        write_buf_format(dbuf, fmt3);
        write_buf_format(dbuf, fmt4, "..", "/", "..",
                          "Parent directory", "/", st_buf.st_size,
                          get_format_data(st_buf.st_mtime));

        while ((dent = readdir(dirp))) {
                const char *s;
                fstatat(dir_fd, dent->d_name, &st_buf, 0);
                if (!S_ISREG(st_buf.st_mode) && !S_ISDIR(st_buf.st_mode))
                        continue;
                if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
                        continue;
                s = S_ISDIR(st_buf.st_mode) ? "/" : "";
                write_buf_format(dbuf, fmt4, dent->d_name, s, dent->d_name,
                           dent->d_name, s, st_buf.st_size,
                           get_format_data(st_buf.st_mtime));
        }
        closedir(dirp);
        return dbuf;
}

