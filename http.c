#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include "template.h"
#include "server.h"
#include "http.h"

void *memmem(const void *haystack, size_t haystacklen,
             const void *needle, size_t needlelen);

static const char *const http_methods[] = {
        "GET", "POST", "PUT", "DELETE"
};

static void set_header(struct http_headers *headers, const char *key, const char *val)
{
        hashmap_insert(headers->index, key, ARRAY_LEN(&headers->values));
        ARRAY_APPEND(&headers->values, strdup(val));
}

static const char *get_header(struct http_headers *headers, const char *key)
{
        uint64_t num = hashmap_search(headers->index, key);
        return num != HASHMAP_MISS ? ARRAY_GET(&headers->values, num) : NULL;
}

static void init_headers(struct http_headers *headers)
{
        ARRAY_INIT(&headers->values, 0);
        headers->index = make_map();
}

static int parse_request_line(struct http_request *req,
                              const char *buf, int size)
{
        int i, index = 0, request_state = 0;
        for (i = 0; i < size; i++) {
                switch (request_state) {
                case 0:
                        if (buf[i] == ' ' || index == method_size - 1) {
                                req->method[index] = 0;
                                index = 0;
                                request_state = 1;
                        } else {
                                req->method[index] = buf[i];
                                index++;
                        }
                        break;
                case 1:
                        if (buf[i] == ' ' || index == path_size - 1) {
                                req->path[index] = 0;
                                index = 0;
                                request_state = 2;
                        } else {
                                req->path[index] = buf[i];
                                index++;
                        }
                        break;
                case 2:
                        if (buf[i] == '\r' || index == proto_size - 1) {
                                req->proto[index] = 0;
                                index = 0;
                                request_state = 3;
                        } else {
                                req->proto[index] = buf[i];
                                index++;
                        }
                        break;
                default:
                        return 0;
                }
        }
        return -1;
}

static int parse_request_headers(struct http_request *req, const char *buf, int size)
{
        static char header_key_buf[header_key_size];
        static char header_val_buf[header_val_size];
        size_t header_key_size, header_val_size;
        char *curr, *end, *next, *colon;

        curr = memmem(buf, size, "\r\n", 2);
        if (!curr)
                return -1;
        end = memmem(buf, size, "\r\n\r\n", 4);
        if (!end)
                return -1;
        req->body_offset = end + 4 - buf;

        for (curr += 2, end += 2; curr != end; curr = next + 2) {
                next = memmem(curr, size - (curr - buf),  "\r\n", 2);
                colon = memmem(curr, next - curr, ": ", 2);
                if (!colon)
                        return -1;
                header_key_size = colon - curr;
                colon += 2;
                header_val_size = next - colon;

                if (header_key_size > sizeof(header_key_buf) - 1 ||
                    header_val_size > sizeof(header_val_buf) - 1)
                        return -1;

                memcpy(header_key_buf, curr, header_key_size);
                memcpy(header_val_buf, colon, header_val_size);
                header_key_buf[header_key_size] = 0;
                header_val_buf[header_val_size] = 0;
                set_header(&req->headers, header_key_buf, header_val_buf);
        }
        return 0;
}

static void parse_request_body(struct http_request *req, const char *buf, int size)
{
        const char *content_len = get_header(&req->headers, "Content-Length");
        req->body_size = content_len ? atol(content_len) : 0;
        req->body_got = size - req->body_offset;
        fprintf(stderr, "body_got = %ld, body_size = %ld\n", req->body_got, req->body_size);
        if (req->body_got >= req->body_size)
                http_set_body(req, buf, size);
}

static const char *get_status_text(enum http_status_constant code)
{
        switch (code) {
        case status_continue:
                return "100 Continue";
        case status_switching_protocols:
                return "101 Switching Protocols";
        case status_processing:
                return "102 Processing";
        case status_early_hints:
                return "103 Early Hints";

        case status_ok:
                return "200 OK";
        case status_created:
                return "201 Created";
        case status_accepted:
                return "202 Accepted";
        case status_non_authoritativeinfo:
                return "203 Non-Authoritative Information";
        case status_no_content:
                return "204 No Content";
        case status_reset_content:
                return "205 Reset Content";
        case status_partial_content:
                return "206 Partial Content";
        case status_multi_status:
                return "207 Multi-Status";
        case status_already_reported:
                return "208 Already Reported";
        case status_im_used:
                return "226 IM Used";
        case status_multiple_choices:
                return "300 Multiple Choices";

        case status_moved_permanently:
                return "301 Moved Permanently";
        case status_found:
                return "302 Found";
        case status_see_other:
                return "303 See Other";
        case status_not_modified:
                return "304 Not Modified";
        case status_use_proxy:
                return "305 Use Proxy";
        case status_temporary_redirect:
                return "307 Temporary Redirect";
        case status_permanent_redirect:
                return "308 Permanent Redirect";

        case status_bad_request:
                return "400 Bad Request";
        case status_unauthorized:
                return "401 Unauthorized";
        case status_payment_required:
                return "402 Payment Required";
        case status_forbidden:
                return "403 Forbidden";
        case status_not_found:
                return "404 Not Found";
        case status_method_not_allowed:
                return "405 Method Not Allowed";
        case status_not_acceptable:
                return "406 Not Acceptable";
        case status_proxy_auth_required:
                return "407 Proxy Authentication Required";
        case status_request_timeout:
                return "408 Request Timeout";
        case status_conflict:
                return "409 Conflict";
        case status_gone:
                return "410 Gone";
        case status_length_required:
                return "411 Length Required";
        case status_precondition_failed:
                return "412 Precondition Failed";
        case status_request_entity_too_large:
                return "413 Request Entity Too Large";
        case status_request_uri_too_long:
                return "414 Request URI Too Long";
        case status_unsupported_media_type:
                return "415 Unsupported Media Type";
        case status_requested_range_not_satisfiable:
                return "416 Requested Range Not Satisfiable";
        case status_expectation_failed:
                return "417 Expectation Failed";
        case status_teapot:
                return "418 I'm a teapot";
        case status_misdirected_request:
                return "421 Misdirected Request";
        case status_unprocessable_entity:
                return "422 Unprocessable Entity";
        case status_locked:
                return "423 Locked";
        case status_failed_dependency:
                return "424 Failed Dependency";
        case status_too_early:
                return "425 Too Early";
        case status_upgrade_required:
                return "426 Upgrade Required";
        case status_precondition_required:
                return "428 Precondition Required";
        case status_too_many_requests:
                return "429 Too Many Requests";
        case status_request_header_fields_too_large:
                return "431 Request Header Fields Too Large";
        case status_unavailable_for_legal_reasons:
                return "451 Unavailable For Legal Reasons";

        case status_internal_server_error:
                return "500 Internal Server Error";
        case status_not_implemented:
                return "501 Not Implemented";
        case status_bad_gateway:
                return "502 Bad Gateway";
        case status_service_unavailable:
                return "503 Service Unavailable";
        case status_gateway_timeout:
                return "504 Gateway Timeout";
        case status_http_version_not_supported:
                return "505 HTTP Version Not Supported";
        case status_variant_also_negotiates:
                return "506 Variant Also Negotiates";
        case status_insufficient_storage:
                return "507 Insufficient Storage";
        case status_loop_detected:
                return "508 Loop Detected";
        case status_not_extended:
                return "510 Not Extended";
        case status_network_authentication_required:
                return "511 Network Authentication Required";
        }
        return "";
}

static const char *get_http_fmt_date(time_t tm)
{
        static char buff[64];
        strftime(buff, sizeof(buff), "%a, %d %b %Y %X %Z", gmtime(&tm));
        return buff;
}

struct request_dbuf {
        struct http_request *req;
        struct data_buffer *dbuf;
};

static void write_buf_header(const char *key, uint64_t num, void *rdp)
{
        struct request_dbuf *rd = rdp;
        write_buf_format(rd->dbuf, "%s: %s\r\n",
                         key, ARRAY_GET(&rd->req->headers.values, num));
}

struct data_buffer *http_get_rawdata(struct http_request *req)
{
        struct request_dbuf rd;
        size_t request_size = request_line_size + req->body_size +
                              header_size * ARRAY_LEN(&req->headers.values) + 2;
        struct data_buffer *dbuf = make_buffer(request_size);
        rd.dbuf = dbuf;
        rd.req = req;
        write_buf_format(dbuf, "%s %s %s\r\n", req->method, req->path, req->proto);
        hashmap_foreach(req->headers.index, write_buf_header, &rd);
        write_buf_format(dbuf, "\r\n");
        write_buf_data(dbuf, req->body, req->body_size);
        return dbuf;
}

struct http_request *http_curl(enum http_method method, const char *path)
{
        struct http_request *req = malloc(sizeof(*req));
        strncpy(req->method, http_methods[method], method_size);
        strncpy(req->proto, "HTTP/1.1", proto_size);
        strncpy(req->path, path, path_size);
        init_headers(&req->headers);
        req->body_size = 0;
        req->body_got = (size_t)-1;
        req->body_offset = 0;
        return req;
}

void free_http_request(struct http_request *req)
{
        if (!req)
                return;
        delete_map(req->headers.index);
        ARRAY_FREE2(&req->headers.values, free);
        free(req->body);
        free(req);
}

const char *http_get_header(struct http_request *req, const char *key)
{
        return get_header(&req->headers, key);
}

void http_set_header(struct http_request *req, const char *key, const char *val)
{
        set_header(&req->headers, key, val);
}

void http_set_body(struct http_request *req, const char *buf, int size)
{
        if (req->body_got == (size_t)-1)
                req->body_size = size;
        req->body = malloc(req->body_size);
        memcpy(req->body, buf + req->body_offset, req->body_size);
}

void http_response(struct session *sess, int code)
{
        struct data_buffer *dbuf = sess->sendbuf;
        write_buf_format(dbuf, "HTTP/1.1 %s\r\n", get_status_text(code));
        write_buf_format(dbuf, "Date: %s\r\n", get_http_fmt_date(time(NULL)));
        write_buf_format(dbuf, "Server: Tiny HTTP Server (Unix)\r\n");
        write_buf_format(dbuf, "Connection: close\r\n");
}

void http_content_headers(struct session *sess, const char *type,
                          size_t length, time_t mt)
{
        struct data_buffer *dbuf = sess->sendbuf;
        write_buf_format(dbuf, "Accept-Ranges: none\r\n");
        write_buf_format(dbuf, "Content-Type: %s\r\n", type);
        write_buf_format(dbuf, "Content-Length: %ld\r\n", length);
        write_buf_format(dbuf, "Last-Modified: %s\r\n", get_http_fmt_date(mt));
}

void http_crlf(struct session *sess)
{
        write_buf_format(sess->sendbuf, "\r\n");
}

int http_check_request_end(const char *buf, int size)
{
        return memmem(buf, size, "\r\n\r\n", 4) ? 1 : 0;
}

struct http_request *http_parse_request(const char *buf, int size)
{
        int res;
        struct http_request *req = malloc(sizeof(*req));
        req->body = NULL;
        init_headers(&req->headers);
        res = parse_request_line(req, buf, size);
        if (res == -1) {
                free_http_request(req);
                return NULL;
        }
        res = parse_request_headers(req, buf, size);
        if (res == -1) {
                free_http_request(req);
                return NULL;
        }
        parse_request_body(req, buf, size);
        return req;
}

