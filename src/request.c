#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <stdint.h>
#include "request.h"

static int map_content_type(struct Request *req);

static int copy_field(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if(n >= cap) return BAD_REQ;
    memcpy(dst, src, n + 1);
    return 0;
}

static int get_method(const char *s)
{
    static const char *methods[] = {"GET", "HEAD", "PUT", "POST", "DELETE", "CONNECT", "OPTIONS", "TRACE"};
    for(int i = 0; i < 8; ++i) if(strcmp(s, methods[i]) == 0) return i;
    return -1;
}

static int token_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static int parse_header(char *head, struct Request *req)
{
    char *end = strstr(head, "\r\n");
    if(!end) return BAD_REQ;
    *end = '\0';
    char *target = strchr(head, ' ');
    if(!target) return BAD_REQ;
    *target++ = '\0';
    char *protocol = strchr(target, ' ');
    if(!protocol) return BAD_REQ;
    *protocol++ = '\0';
    req->method = get_method(head);
    if(req->method < 0 || !*target ||
       (strcmp(protocol, "HTTP/1.1") && strcmp(protocol, "HTTP/1.0"))) return BAD_REQ;
    if(copy_field(req->resource, sizeof(req->resource), target) ||
       copy_field(req->protocol, sizeof(req->protocol), protocol)) return BAD_REQ;
    for(const unsigned char *p = (unsigned char *)target; *p; ++p)
        if(*p <= 0x20 || *p == 0x7f) return BAD_REQ;

    int host_seen = 0, cl_seen = 0;
    req->cont_length = 0;
    for(char *line = end + 2; *line; line = end + 2){
        end = strstr(line, "\r\n");
        if(!end) return BAD_REQ;
        if(end == line) break;
        *end = '\0';
        char *value = strchr(line, ':');
        if(!value || value == line) return BAD_REQ;
        *value++ = '\0';
        for(const unsigned char *p = (unsigned char *)line; *p; ++p)
            if(!token_char(*p)) return BAD_REQ;
        while(*value == ' ' || *value == '\t') ++value;
        char *tail = end;
        while(tail > value && (tail[-1] == ' ' || tail[-1] == '\t')) *--tail = '\0';
        for(const unsigned char *p = (unsigned char *)value; *p; ++p)
            if((*p < 0x20 && *p != '\t') || *p == 0x7f) return BAD_REQ;
        if(!strcasecmp(line, "Host")){
            if(host_seen++ || !*value || copy_field(req->host, sizeof(req->host), value)) return BAD_REQ;
        } else if(!strcasecmp(line, "Content-Length")){
            if(cl_seen++ || !*value) return BAD_REQ;
            size_t n = 0;
            for(const unsigned char *p = (unsigned char *)value; *p; ++p){
                if(*p < '0' || *p > '9' || n > (MAX_REQUEST_SIZE - (*p - '0')) / 10) return BAD_REQ;
                n = n * 10 + *p - '0';
            }
            req->cont_length = n;
        } else if(!strcasecmp(line, "Transfer-Encoding")){
            /* Chunked request decoding is not implemented. Never guess framing. */
            return BAD_REQ;
        } else {
#define FIELD(name, member) if(!strcasecmp(line, name)) { \
    if(copy_field(req->member, sizeof(req->member), value)) return BAD_REQ; \
    continue; }
            FIELD("Content-Type", cont_type)
            FIELD("Connection", connection)
            FIELD("Origin", origin)
            FIELD("Access-Control-Request-Headers", access_control_request_headers)
            FIELD("Access-Control-Request-Method", access_control_request_method)
#undef FIELD
        }
    }
    if(!strcmp(req->protocol, "HTTP/1.1") && !host_seen) return BAD_REQ;
    return 0;
}

int handle_request(struct Request *req)
{
    if(!req || req->size < 0 || (size_t)req->size > MAX_REQUEST_SIZE ||
       (!req->d_req && (size_t)req->size > sizeof(req->req))) return BAD_REQ;
    char *raw = req->d_req ? req->d_req : req->req;
    int h_end = find_headers_end(raw, req->size);
    if(h_end < 0) return req->size >= MAX_HEADER_SIZE ? BAD_REQ : BDY_MISS;
    if(h_end > MAX_HEADER_SIZE || memchr(raw, '\0', h_end)) return BAD_REQ;
    char *head = malloc((size_t)h_end + 1);
    if(!head) return BAD_REQ;
    memcpy(head, raw, h_end);
    head[h_end] = '\0';
    int status = parse_header(head, req);
    free(head);
    if(status != 0) return BAD_REQ;
    size_t body_size = (size_t)req->cont_length;
    if(body_size > MAX_REQUEST_SIZE - (size_t)h_end) return BAD_REQ;
    if((size_t)req->size - h_end < body_size) return BDY_MISS;
    /* Each connection serves one request; do not absorb trailing requests. */
    free(req->req_body.d_cont);
    req->req_body.d_cont = NULL;
    req->req_body.size = body_size;
    char *body = req->req_body.content;
    if(body_size >= sizeof(req->req_body.content)){
        body = calloc(body_size + 1, 1);
        if(!body) return BAD_REQ;
        req->req_body.d_cont = body;
    }
    memcpy(body, raw + h_end, body_size);
    body[body_size] = '\0';
    if(req->method == GET || req->method == HEAD) map_content_type(req);
    return 0;
}

/* Grow capacity without changing the number of received bytes. */
int set_up_request(ssize_t bytes, struct Request *req)
{
    if(!req || bytes <= 0 || (size_t)bytes > MAX_REQUEST_SIZE || req->size < 0 ||
       (size_t)req->size > (size_t)bytes) return -1;
    size_t cap = (size_t)bytes > MAX_REQUEST_SIZE / 2 ? MAX_REQUEST_SIZE : (size_t)bytes * 2;
    if(req->d_req && req->capacity >= cap) return 0;
    char *p = realloc(req->d_req, cap);
    if(!p) return -1;
    if(!req->d_req) memcpy(p, req->req, req->size);
    req->d_req = p;
    req->capacity = cap;
    return 0;
}

void clear_request(struct Request *req)
{
    if(!req) return;
    free(req->d_req);
    free(req->req_body.d_cont);
    memset(req, 0, sizeof(*req));
}

int find_headers_end(char *buffer, size_t size)
{
    if(!buffer || size < 4) return -1;
    for(size_t i = 0; i <= size - 4 && i <= INT_MAX - 4; ++i)
        if(memcmp(buffer + i, "\r\n\r\n", 4) == 0) return (int)i + 4;
    return -1;
}

static int map_content_type(struct Request *req)
{
	if(strstr(req->resource,".html")) {
		strncpy(req->cont_type,"text/html",MIN_HEAD_FIELD);
		return 0;
	} 

	if(strncmp(req->resource,"/", 2) == 0) {
		strncpy(req->cont_type,"text/html",MIN_HEAD_FIELD);
		return 0;
	} 

	if(strstr(req->resource,".css")) {
		strncpy(req->cont_type,"text/css",MIN_HEAD_FIELD);
		return 0;
	} 
	if(strstr(req->resource,".js")) {
		strncpy(req->cont_type,"text/javascript",MIN_HEAD_FIELD);
		return 0;
	} 
	if(strstr(req->resource,".jpeg")) {
		strncpy(req->cont_type,"image/jpeg",MIN_HEAD_FIELD);
		return 0;
	} 

	if(strstr(req->resource,".png")) {
		strncpy(req->cont_type,"image/png",MIN_HEAD_FIELD);
		return 0;
	} 

	if(strstr(req->resource,".json")) {
		strncpy(req->cont_type,"application/json",MIN_HEAD_FIELD);
		return 0;
	} 
	
	strncpy(req->cont_type,"text/html",MIN_HEAD_FIELD);
	return 0;
}
