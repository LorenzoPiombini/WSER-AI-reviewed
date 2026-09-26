#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "response.h"
#include "default.h"

static char prog[] = "Wser";
static int set_up_headers(struct Header *headers, int status, size_t body_size);
static void set_status_and_phrase(struct Header *headers, uint16_t status);
static char *create_response_message(struct Response *res, int status, struct Content *cont, struct Request *req);
static int parse_body(struct Content *cont, struct Response *res);
static int not_found_header(char *header, struct Request *req, struct Response *res, struct Content *cont);
static int bad_request_header(char *header,struct Content *cont);
static int moved_permanently_header(char *header,struct Request *r);
static int options_response_header(char *header,int status);
static int server_error_header(char *header);
static char *month_parser(int month);
static char *day_parser(int day);
static char *second_parser(int second);
static char *date_formatter();

int generate_response(struct Response *res, int status, struct Content *cont, struct Request *req){
	char *h = create_response_message(res,status,cont,req);
	if (!h) return -1;

	snprintf(res->header_str, sizeof(res->header_str), "%s", h);
    res->sent = 0;
	if(cont && status != 301 && status != 500 && (req->method != OPTIONS || status != 200)){
        if(parse_body(cont,res) == -1) return -1;
    } else if(status == 400 && !cont){
        memcpy(res->body.content, BAD_REQ_MES, sizeof(BAD_REQ_MES) - 1);
        res->body.size = sizeof(BAD_REQ_MES) - 1;
    }
    if(req->method == HEAD) res->body.size = 0;

	return 0;
}

void clear_response(struct Response *res)
{
	if(res->body.d_cont) free(res->body.d_cont);

	memset(res,0,sizeof(struct Response));
}

static char *create_response_message(struct Response *res, int status, struct Content *cont, struct Request *req)
{
	if(set_up_headers(&res->headers,status,cont == NULL ? 0 :cont->size) == -1) return NULL;
	static char h[STD_HD_L] = {0};

	switch(status){
	case 404:
		if(not_found_header(h,req,res,cont != NULL ? cont : NULL) == -1) return NULL;
		return h;
	case 400:
		if(bad_request_header(h,cont) == -1) return NULL;
		return h;
	case 301:
		if(moved_permanently_header(h,req) == -1) return NULL;
		return h;
	case 500:
		if(server_error_header(h) == -1) return NULL;
        memcpy(res->body.content, SERVER_ER_MES, sizeof(SERVER_ER_MES) - 1);
        res->body.size = sizeof(SERVER_ER_MES) - 1;
        return h;
	default:
		break;
	}

	if(req->method == OPTIONS){
		if(options_response_header(h,status) == -1) return NULL;

		return h;
	}
/*
	if(strstr(req->resource,".js") || 
				strstr(req->resource, ".css")){
		if(strncmp(res->headers.protocol_vs,DEFAULT,STD_LEN_PTC) == 0){
			if(snprintf(h,1024,"%s %u %s\r\n"\
					"%s: %s\r\n"\
					"%s: %s\r\n"\
					"%s: %ld\r\n"\
					"%s: %s\r\n"\
					"%s: %s\r\n"\
					"\r\n",res->headers.protocol_vs, res->headers.status, res->headers.reason_phrase,
					"Date", res->headers.date,
					"Content-Type",req->cont_type,
					"Content-Length",(cont ? cont->size : 0),
					"Connection",res->headers.connection,
					"Cache-Control","max-age=10800") == -1){

			return NULL;
			}
		}else if(strncmp(res->headers.protocol_vs,HTTP2,STD_LEN_HTTP2) == 0){
			if(snprintf(h,1024,"%s %u %s\r\n"\
						"%s: %s\r\n"\
						"%s: %ld\r\n"\
						"%s: %s\r\n"\
						"\r\n", res->headers.protocol_vs, res->headers.status, res->headers.reason_phrase,
						"Date", res->headers.date,
						"Content-Length",(cont ? cont->size : 0),
						"Content-Type",req->cont_type) == -1){
				return NULL;
			}
		}

	}else{
	*/
		if(strncmp(res->headers.protocol_vs,DEFAULT,STD_LEN_PTC) == 0){
			if(snprintf(h,1024,"%s %u %s\r\n"\
						"%s: %s\r\n"\
						"%s: %s\r\n"\
						"%s: %ld\r\n"\
						"%s: %s\r\n"\
						"\r\n",res->headers.protocol_vs, res->headers.status, res->headers.reason_phrase,
						"Date", res->headers.date,
						"Content-Type",req->cont_type,
						"Content-Length",(cont ? cont->size : 0),
						"Connection",res->headers.connection) == -1){

				return NULL;
			}
		}else if(strncmp(res->headers.protocol_vs,HTTP2,STD_LEN_HTTP2) == 0){
			if(snprintf(h,1024,"%s %u %s\r\n"\
						"%s: %s\r\n"\
						"%s: %ld\r\n"\
						"%s: %s\r\n"\
						"\r\n", res->headers.protocol_vs, res->headers.status, res->headers.reason_phrase,
						"Date", res->headers.date,
						"Content-Length",(cont ? cont->size : 0),
						"Content-Type",req->cont_type) == -1){
				return NULL;
			}
		}
	/*}*/
	return h;
}


static int set_up_headers(struct Header *headers, int status, size_t body_size)
{
	set_status_and_phrase(headers,(uint16_t)status);
	strncpy(headers->protocol_vs,STD_PTC,STD_LEN_PTC);

	if(status > 400 || status < 203){ 
		char *date = date_formatter();
		if(!date) return -1;
		strncpy(headers->date,date,50); 
		strncpy(headers->connection,"close",50);
	}

	if (body_size > 0) headers->content_lenght = body_size;

	return 0;
}

static void set_status_and_phrase(struct Header *headers, uint16_t status)
{
	switch(status){
		case 100:
			headers->status = status;
			strncpy(headers->reason_phrase,"Continue",50);
			break;
		case 101  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Switching Protocols",50);
			break;
		case 200:   
			headers->status = status;
			strncpy(headers->reason_phrase,"OK",50);
			break;
		case 201:
			headers->status = status;
			strncpy(headers->reason_phrase,"Created",50);
			break;

		case 202  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Accepted",50);
			break;

		case 203  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Non-Authoritative Information",50);
			break;

		case 204  :
			headers->status = status;
			strncpy(headers->reason_phrase,"No Content",50);
			break;

		case 205  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Reset Content",50);
			break;

		case 206  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Partial Content",50);
			break;

		case 300  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Multiple Choices",50);
			break;

		case 301  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Moved Permanently",50);
			break;

		case 302  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Found",50);
			break;

		case 303  :
			headers->status = status;
			strncpy(headers->reason_phrase,"See Other",50);
			break;

		case 304  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Not Modified",50);
			break;

		case 305  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Use Proxy",50);
			break;

		case 307  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Temporary Redirect",50);
			break;

		case 400  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Bad Request",50);
			break;

		case 401  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Unauthorized",50);
			break;

		case 402  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Payment Required ",50);
			break;

		case 403  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Forbidden",50);
			break;

		case 404  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Not Found",50);
			break;

		case 405  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Method Not All",50);
			break;

		case 406  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Not Acceptabl",50);
			break;

		case 407  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Proxy Authen",50);
			break;

		case 408  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Request Tim",50);
			break;

		case 409  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Conflict",50);
			break;

		case 410  :
			headers->status = status;
			strncpy(headers->reason_phrase,"Gone",50);
			break;

		case 411  :
			headers->status = status;
		strncpy(headers->reason_phrase,"Length R",50);
		break;
	       
	case 412  :
		headers->status = status;
		strncpy(headers->reason_phrase,"Precond",50);
		break;
		       
	case 413  :
		headers->status = status;
		strncpy(headers->reason_phrase,"Payloa",50);
		break;
	       
	case 414  :
		headers->status = status;
		strncpy(headers->reason_phrase,"URI T",50);
		break;
	       
	case 415  :
		headers->status = status;
		strncpy(headers->reason_phrase,"Unsupported Media Type",50);
		break;
	      
	case 416  :
		headers->status = status;
		strncpy(headers->reason_phrase,"Range Not Satisfiable",50);
		break;
	       
	case 417  :
		headers->status = status;
		strncpy(headers->reason_phrase,"Expectation Failed",50);
		break;
	       
	case 426  :
		headers->status = status;
		strncpy(headers->reason_phrase,"Upgrade Required",50);
		break;
	       
	case 500  :
		headers->status = status;
		strncpy(headers->reason_phrase,"Internal Server Error",50);
		break;
	       
	case 501  :
		headers->status = status;
		strncpy(headers->reason_phrase,"Not Implemented",50);
		break;
	       
	case 502  :
		headers->status = status;
		strncpy(headers->reason_phrase,"Bad Gateway",50);
		break;
	       
	case 503  :
		headers->status = status;
		strncpy(headers->reason_phrase,"Service Unavailable",50);
		break;
	       
	case 504  :
		headers->status = status;
		strncpy(headers->reason_phrase,"Gateway Timeout",50);
		break;
	      
	case 505  :
		headers->status = status;
		strncpy(headers->reason_phrase,"HTTP Version Not Supported",50);
		break;
	       
	default:
		break;
	}
}

static int parse_body(struct Content *cont, struct Response *res)
{
	if(cont->size < STD_BDY_CNT){
		if(cont->cnt_dy)
			memcpy(res->body.content,cont->cnt_dy,cont->size);
		else
			memcpy(res->body.content,cont->cnt_st,cont->size);
		
		res->body.size = cont->size;
		return 0;
	}
	
	res->body.d_cont = calloc(cont->size+1,sizeof(char));
	if(!res->body.d_cont) return -1;

	memcpy(res->body.d_cont,cont->cnt_dy,cont->size);
	res->body.size = cont->size;

	return 0;
}
static int not_found_header(char *header, struct Request *req, struct Response *res, struct Content *cont)
{
    (void)req;
    size_t size = cont ? cont->size : sizeof(NOT_FOUND) - 1;
    if(!cont){
        memcpy(res->body.content, NOT_FOUND, size);
        res->body.size = size;
    }
    int n = snprintf(header, STD_HD_L,
        "HTTP/1.1 404 Not Found\r\nDate: %s\r\nContent-Type: text/html\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n", res->headers.date, size);
    return n < 0 || n >= STD_HD_L ? -1 : 0;
}

static int bad_request_header(char *header,struct Content *cont)
{
	if(snprintf(header,1024,"%s %d %s\r\n"\
				"Content-Type: %s\r\n"\
				"Content-Length: %ld\r\n\r\n","HTTP/1.1", 400, "Bad request",
				"application/json",
				cont == NULL ? strlen(BAD_REQ_MES) : cont->size) == -1){
		fprintf(stderr,"(%s): cannot form BAD RESPONSE.",prog);
		return -1;
	}
	return 0;
}

static int server_error_header(char *header){
	if(snprintf(header,1024,"%s %d %s\r\n"\
				"Content-Type: %s\r\n"\
				"Content-Length: %ld\r\n\r\n","HTTP/1.1", 500, "Internal Server Error",
				"application/json",strlen(SERVER_ER_MES)) == -1){
		fprintf(stderr,"(%s): cannot form 500 RESPONSE.",prog);
		return -1;
	}
	return 0;
}

static int moved_permanently_header(char *header,struct Request *r)
{
	if(snprintf(header,1024,"HTTP/1.1 301 Moved Permanently\r\n"\
							"Location: %s%s\r\n"\
    						"Content-Length: 0\r\n"\
        					"Connection: close\r\n\r\n",REDIRECT_DEFAULT_DOMAIN,r->resource) == -1){
		fprintf(stderr,"(%s): cannot form 301 response.",prog);
		return -1;
	}
	return 0;
}

static int options_response_header(char *header, int status)
{
	char *mess = "Response";
	if(status == 200) mess = "OK";
	if(snprintf(header,1024,"%s %d %s\r\n"\
				"Access-Control-Allow-Origin: %s\r\n"\
				"Access-Control-Allow-Methods: %s, %s\r\n"\
				"Access-Control-Allow-Headers: %s\r\n"\
				"Access-Control-Max-Age: %u\r\n"\
                "Content-Length: 0\r\n\r\n",
				"HTTP/1.1", status,mess,
				ORIGIN_DEF,"GET","OPTIONS",
				"Content-type",SECONDS_IN_A_DAY) == -1){
		fprintf(stderr,"(%s): cannot form BAD RESPONSE.",prog);
		return -1;
	}
	return 0;
}

static char *date_formatter()
{
 	static char date [50] = {0};

	time_t t =0;
	if((t = time(NULL)) == -1) return NULL;
	struct tm *d = gmtime(&t);
	if(!d) return NULL;

	
	if(snprintf(date,50,"%s, %02d %s %d %02d:%02d:%s GMT",day_parser(d->tm_wday),
				d->tm_mday,month_parser(d->tm_mon), d->tm_year + 1900,
				d->tm_hour,d->tm_min,second_parser(d->tm_sec)) == -1) return NULL;
	
	return date;

}

static char *day_parser(int day)
{
	switch(day){
	case 0: return "Sun";
	case 1: return "Mon";
	case 2: return "Tue";
	case 3: return "Wed";
	case 4: return "Thu";
	case 5: return "Fri";
	case 6: return "Sat";
	default: return NULL;
	}
}
static char *month_parser(int month)
{
	switch(month){
	case 0: return "Jan";
	case 1: return "Feb";
	case 2: return "Mar";
	case 3: return "Apr";
	case 4: return "May";
	case 5: return "Jun";
	case 6: return "Jul";
	case 7: return "Aug";
	case 8: return "Sep";
	case 9: return "Oct";
	case 10: return "Nov";
	case 11: return "Dec";
	default: return NULL;
	}

}
static char *second_parser(int second)
{
	switch(second){
	case 0 : return "00";
	case 1 : return "01";
	case 2 : return "02";
	case 3 : return "03";
	case 4 : return "04";
	case 5 : return "05";
	case 6 : return "06";
	case 7 : return "07";
	case 8 : return "08";
	case 9 : return "09";
	default:
	{
		static char num [3] = {0};
		if(snprintf(num,3,"%d",second) == -1 ) return NULL;
		return num;
	}
	}
}
