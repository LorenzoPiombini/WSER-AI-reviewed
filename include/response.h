#ifndef _RESPONSE_H_
#define _RESPONSE_H_


#include <stdint.h>
#include "request.h"
#include "load.h"
#define STD_PTC "HTTP/1.1"
#define STD_LEN_PTC 9
#define STD_LEN_HTTP2 7 
#define STD_BDY_CNT 8192
#define STD_HD_L 1024
#define SECONDS_IN_A_DAY (60 * 60 * 24)
#define BAD_REQ_MES "{\"error\": \"Bad request\",\"message\": \"Request body could not be read properly.\"}"
#define SERVER_ER_MES "{\"error\": \"Server internal error\",\"message\": \"contact assistance@artech.com .\"}"
#define ALLOWED_METHODS "GET, POST, OPTIONS"

#define OPTIONS_RESPONSE 		3855 	/*00001111 00001111*/
#define BAD_REQ_RESPONSE 		7 	/*00000000 00000111*/
#define NOT_FOUND_RESPONSE 		15 	/*00000000 00001111*/
#define OK_GET_RESPONSE 		23 	/*00000000 00010111*/
#define OK_GET_RESPONSE_BODY		32791 	/*10000000 00010111*/
#define OK_POST_RESPONSE	 	103 	/*00000000 01100111*/
#define OK_CREATED_POST_RESPONSE 	55 	/*00000000 00110111*/
#define SERVER_ERROR 			32768 	/*1000 0000 0000 0000*/

struct Header{
	uint16_t status;
	char protocol_vs[STD_LEN_PTC];
	char reason_phrase[MIN_HEAD_FIELD];
	char date[MIN_HEAD_FIELD];
	uint32_t content_lenght;
	char cont_type[MIN_HEAD_FIELD];
	char connection[MIN_HEAD_FIELD];
	char keep_alive[MIN_HEAD_FIELD]; /*only for HTTP 1.1*/
	char transfer_encoding[MIN_HEAD_FIELD];
	/*fields for OPTIONS responses*/
	char access_control_allow_origin[MIN_HEAD_FIELD];
	char access_control_allow_methods[MIN_HEAD_FIELD];
	char access_control_allow_headers[MIN_HEAD_FIELD];
	uint32_t access_control_max_age; 
};

struct Body {
	char content[STD_BDY_CNT];	
	char *d_cont;
	size_t size;
};

struct Response{
	struct Header headers;
	char header_str[STD_HD_L];
	struct Body body;
	size_t sent; /* bytes already sent by write_cli_sock */
};




int generate_response(struct Response *res, int status, struct Content *cont, struct Request *req);
void clear_response(struct Response *res);
#endif
