#ifndef TEMPLATE_H_SENTRY
#define TEMPLATE_H_SENTRY

struct session;

void write_buf_format(struct session *sess, const char *fmt, ...); 

void generate_index_page(struct session *sess, const char *path, int dir_fd); 

#endif

