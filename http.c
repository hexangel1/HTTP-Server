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

void *http_check_request_end(const char *buf, int size)
{
        return size >= 4 && memcmp(buf + size - 4, "\r\n\r\n", 4) ? NULL : (void *)buf;
}

struct http_request *http_parse_request(const char *buf, int size)
{
        int res;
        struct http_request *req = malloc(sizeof(*req));
        res = parse_request_line(req, buf, size);
        if (res == -1) {
                free(req);
                return NULL;
        }
        return req;
}

