#ifndef _REQUEST_H_
#define _REQUEST_H_ 1

#include <stddef.h>
#include <sys/types.h>

#define MAX_HEADER_SIZE (16 * 1024)
#define MAX_REQUEST_SIZE (1024U * 1024U)

#define STD_REQ_BDY_CNT	8192
#define MIN_HEAD_FIELD 50
#define BASE 1024*2
#define BAD_REQ 400
#define BDY_MISS 600
#define OK 200 
#define OK_CREATE 201 
#define STD_LT_RESOURCE 550
#define DEFAULT "HTTP/1.1"
#define HTTP2 "HTTP/2"
#define KEEP_ALIVE "keep-alive"

/*TODO: make this macro a configuration type of thing*/
#define ORIGIN_DEF "http://artech:8080"

enum method{
	GET,
	HEAD,
	PUT,
	POST,
	DELETE,
	CONNECT,
	OPTIONS,
	TRACE
};

struct r_body{
	char content[STD_REQ_BDY_CNT];	
	char *d_cont;
	size_t size;
};

struct Request{
	char req[BASE];
	char *d_req;
	ssize_t size;
	size_t capacity; /* dynamic raw request capacity */
	int method;
	char protocol[MIN_HEAD_FIELD];
	char host[MIN_HEAD_FIELD];
	char resource[STD_LT_RESOURCE];
	char connection[STD_LT_RESOURCE];

	/*rapresentation header*/
	char cont_type[MIN_HEAD_FIELD];
	ssize_t cont_length;
	char transfer_encoding[MIN_HEAD_FIELD];

	/*fields from OPTIONS method request (LIKE CORS browser preflight)*/
	char access_control_request_headers[MIN_HEAD_FIELD];
	char access_control_request_method[MIN_HEAD_FIELD]; 
	char origin[MIN_HEAD_FIELD];
	struct r_body req_body; 
};

int handle_request(struct Request *req);
int set_up_request(ssize_t len,struct Request *req);
int find_headers_end(char *buffer, size_t size);
void clear_request(struct Request *req);
#endif
