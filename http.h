#ifndef HTTP_H_SENTRY
#define HTTP_H_SENTRY

#include <stdlib.h>
#include "hashmap.h"

enum http_status_constant {
        status_continue            = 100,
        status_switching_protocols = 101,
        status_processing          = 102,
        status_early_hints         = 103,

        status_ok                    = 200,
        status_created               = 201,
        status_accepted              = 202,
        status_non_authoritativeinfo = 203,
        status_no_content            = 204,
        status_reset_content         = 205,
        status_partial_content       = 206,
        status_multi_status          = 207,
        status_already_reported      = 208,
        status_im_used               = 226,

        status_multiple_choices   = 300,
        status_moved_permanently  = 301,
        status_found              = 302,
        status_see_other          = 303,
        status_not_modified       = 304,
        status_use_proxy          = 305,
        status_temporary_redirect = 307,
        status_permanent_redirect = 308,

        status_bad_request                     = 400,
        status_unauthorized                    = 401,
        status_payment_required                = 402,
        status_forbidden                       = 403,
        status_not_found                       = 404,
        status_method_not_allowed              = 405,
        status_not_acceptable                  = 406,
        status_proxy_auth_required             = 407,
        status_request_timeout                 = 408,
        status_conflict                        = 409,
        status_gone                            = 410,
        status_length_required                 = 411,
        status_precondition_failed             = 412,
        status_request_entity_too_large        = 413,
        status_request_uri_too_long            = 414,
        status_unsupported_media_type          = 415,
        status_requested_range_not_satisfiable = 416,
        status_expectation_failed              = 417,
        status_teapot                          = 418,
        status_misdirected_request             = 421,
        status_unprocessable_entity            = 422,
        status_locked                          = 423,
        status_failed_dependency               = 424,
        status_too_early                       = 425,
        status_upgrade_required                = 426,
        status_precondition_required           = 428,
        status_too_many_requests               = 429,
        status_request_header_fields_too_large = 431,
        status_unavailable_for_legal_reasons   = 451,

        status_internal_server_error           = 500,
        status_not_implemented                 = 501,
        status_bad_gateway                     = 502,
        status_service_unavailable             = 503,
        status_gateway_timeout                 = 504,
        status_http_version_not_supported      = 505,
        status_variant_also_negotiates         = 506,
        status_insufficient_storage            = 507,
        status_loop_detected                   = 508,
        status_not_extended                    = 510,
        status_network_authentication_required = 511
};

enum http_request_constant {
        method_size     = 16,
        path_size       = 256,
        proto_size      = 16,
        header_key_size = 1024,
        header_val_size = 1024,

        request_line_size = method_size + path_size + proto_size + 4,
        header_size = header_key_size + header_val_size + 4
};

struct http_headers {
        int header_number;
        int header_allocated;
        char **header_values;
        struct hashmap *header_idx;
};

struct http_request {
        char method[method_size];
        char path[path_size];
        char proto[proto_size];
        struct http_headers headers;
        char *body;
        size_t body_size;
        size_t body_offset;
        size_t body_got;
};

struct session;

/* write http response to buffer */
void http_response(struct session *sess, int code);

/* write http content headers to buffer */
void http_content_headers(struct session *sess, const char *type,
                          size_t length, time_t mtime);

/* write cr & lf to buffer */
void http_crlf(struct session *sess);

/* http_check_request_end checks is the request finished */
int http_check_request_end(const char *buf, int size);

/* http_parse_request return parsed http request */
struct http_request *http_parse_request(const char *buf, int size);

void free_http_request(struct http_request *req);

void http_set_body(struct http_request *req, const char *buf, int size);

struct data_buffer *http_get_rawdata(struct http_request *req);

#endif /* HTTP_H_SENTRY */

