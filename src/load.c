#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include "load.h"
#include "request.h"
#include "default.h"
#include "json.h"

static char prog[] = "wser";
static char *map_rpath(char *rpath);
static int check_URL_encoding(char *p);

#define MAX_LOADABLE_FILE (16U * 1024U * 1024U)

#ifdef OWN_DB

#include "worker_process.h" /* database handler*/
#include "end_points.h"
#include "lua_start.h"
#include "ctype.h"
#include <assert.h>
const int EIGHTkib_limit = 1024 * 8;
static int key_allowed(char **wlist,const char* json, struct Json_token *k);
/*orgainizing JSON token,functions*/
static int serialize(const char* json, struct Json_token *t, uint8_t *buffer, size_t buf_size,size_t *bwritten,int token_nr);
static int ser_flat_object(const char *json,struct Json_token *t,uint8_t *buffer,size_t buf_size,size_t *bwritten);
static int ser_array(const char *json,struct Json_token *t,uint8_t *buffer,size_t buf_size,size_t *bwritten,int *cursor);
static int check_key_in_object(char **allowed,const char *json,struct Json_token *t,int *i,int *seen);
#endif

int load_resource(char *rpath, struct Content *cont)
{

	if(!rpath || !cont) return -1;

	char *file_path = map_rpath(rpath);
	if(!file_path) {
		/*debug print*/
		fprintf(stderr,"map_rpath failed for some reason\nrpath is %s\n",rpath);
		return -1;
	}

	int fd = open(getuid() == 0 ? "/www" : "./www",O_RDONLY | O_DIRECTORY | O_CLOEXEC |  O_NOFOLLOW);
	if(fd == -1){
		 return -1;
	}

	char *part = file_path + 1;
	for(;;){
		char *slash = strchr(part,'/');
		if (slash) *slash = '\0';

		int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
		if(slash) flags |= O_DIRECTORY;

		errno = 0;
		int resource = openat(fd,part,flags);
		if(resource == -1){
			close(fd);
			strncpy(cont->cnt_st,NOT_FOUND,strlen(NOT_FOUND)+1);
			cont->size = strlen(NOT_FOUND);
			fprintf(stderr,"(%s): cannot open '%s'.\n",prog,rpath);
			if(errno == ELOOP) fprintf(stderr,"they were trying to open a link\n");
			return -1;
		}

		close(fd);
		fd = resource;
		if(!slash) break;
		part = slash + 1;
	}

    struct stat st;
    if(fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
       st.st_size < 0 || st.st_size > MAX_LOADABLE_FILE){
        close(fd);
        return -1;
    }
    size_t length = (size_t)st.st_size;
	char *buf = cont->cnt_st;
	char *allocated  = NULL;

	if(length >= sizeof(cont->cnt_st)){
		allocated = malloc(length +1);
		if(!allocated){
			fprintf(stderr,"(%s): malloc() failed.%s:%d\n",prog,__FILE__,__LINE__-2);
			close(fd);
			return -1;
		}
		buf = allocated;
		memset(buf,0,length+1);
	}

    size_t received = 0;
    while(received < length){
        ssize_t n = read(fd, buf + received, length - received);
        if(n > 0){ received += (size_t)n; continue; }
        if(n < 0 && errno == EINTR) continue;
        free(allocated);
        close(fd);
        return -1;
    }

	buf[length] = '\0';
	close(fd);
	cont->size = length;
	if(allocated) cont->cnt_dy = buf;
	return 0;
}


static int url_hex(unsigned char c)
{
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char *map_rpath(char *rpath)
{
    if(*rpath != '/') return NULL;
    static char path[1024];
    size_t end = strcspn(rpath, "?#"), j = 0;
    for(size_t i = 0; i < end; ++i){
        unsigned char c = rpath[i];
        if(c == '%'){
            if(end - i < 3) return NULL;
            int high = url_hex(rpath[i+1]), low = url_hex(rpath[i+2]);
            if(high < 0 || low < 0) return NULL;
            c = (high << 4) | low;
            i += 2;
        }
        if(c < 0x20 || c == 0x7f || c == '\\' || j + 1 >= sizeof(path)) return NULL;
        path[j++] = c;
    }
    path[j] = 0;
    /* Check decoded path components, including percent-encoded slashes. */
    for(char *part = path + 1; *part;){
        size_t n = strcspn(part, "/");
        if((n == 1 && part[0] == '.') || (n == 2 && !memcmp(part, "..", 2))) return NULL;
        part += n;
        if(*part) ++part;
    }
    if(j == 1) memcpy(path, "/index.html", sizeof("/index.html"));
    return path;
}

void clear_content(struct Content *cont){
	if(cont->cnt_dy) free(cont->cnt_dy);
	cont->cnt_dy = NULL;

	memset(cont->cnt_st,0,MAX_CONT_SZ);
	cont->size = 0;
}	

/*
 * this will change depends on the bussines
 * that you want to manage.
 *  
 *  this is just a sales order system
 * */
#ifdef OWN_DB
#define MAX_KEY_ALLOWED 200
static const char *CUSTOMER_FILEDS[] = {
	"name", "addr", "csz", "country", "phone", "fax", "email", "price_level_id",NULL
	};

static const char *ITEM_FIELDS[] = {
	"name","uom","price_level_id","unit_price", "recipe_id", NULL
};
static const char *NEW_ORD_FIELDS[] = {
	"sales_orders_head","date","customer_id","price_level_id","lines_nr","sales_orders_lines","item_id","qty","uom","unit_price","request_date","disc",NULL
};

int load_resource_db(struct Request *req, struct Content *cont,int data_sock)
{
	int resource = map_end_point(req->resource); 
	if(resource == -1) return 400;

	switch(req->method){
	case POST:
	{
		/* parse json */
		struct Json_token tokens[JSON_MAX_TOKENS] = {0};
		size_t json_len = (size_t)req->req_body.size;
		char *preq = NULL;
		if(req->req_body.d_cont){
			preq = req->req_body.d_cont;
		}else{
			preq = req->req_body.content;
		}

		int token_nr = json_parser((const char *)preq,json_len,tokens,JSON_MAX_TOKENS);

		switch(token_nr){
			case 0:
			case JSON_INVALID_ERR:
			case JSON_DEPTH_LIMIT_ERR:
			case JSON_TK_LIMIT_ERR:
				return 400;
			default: break;
		}

		if(tokens[0].type != OBJECT_JS) return 400;

		switch(resource){
		case N_ITEM:
		case NEW_CUST:
		{
			if(tokens[0].size * 2 + 1 != token_nr) return 400; 
			char **allowed = (resource == NEW_CUST) ? (char**)CUSTOMER_FILEDS : (char**)ITEM_FIELDS;

			/*check the keys*/
			int need_mem = 0;
			int seen[MAX_KEY_ALLOWED] = {0};
			for(int m = 0; m < tokens[0].size; m++){
				int ki = 1 + m * 2;
				int vi = 2 + m * 2;

				if(vi >= token_nr) return 400;
				if(tokens[ki].type != STRING_JS) return 400;
				int idx = key_allowed(allowed,preq,&tokens[ki]);
				if(idx == -1) return 400; /*key not allowed*/
				if(seen[idx]) return 400; /*duplicate key*/
				seen[idx]++;

				need_mem += (tokens[ki].end - tokens[ki].start) + sizeof(uint8_t) + sizeof(uint16_t);
				need_mem += (tokens[vi].end - tokens[vi].start) + sizeof(uint8_t) + sizeof(uint16_t);
			}

			/*DATA IS GOOD*/

			size_t size_buffer = sizeof(uint64_t) + (sizeof(uint16_t) * 2) + need_mem;
			uint8_t *b = malloc(size_buffer);
			if(!b){
				fprintf(stderr,"(%s): malloc() failed, %s:%d.\n",prog,__FILE__,__LINE__);
				return -1;
			}
			memset(b,0,size_buffer);

			size_t bwritten = 0;
			memcpy(&b[bwritten],&resource,sizeof(uint16_t));
			bwritten += sizeof(uint16_t);

			memcpy(&b[bwritten],&size_buffer,sizeof(uint64_t));
			bwritten += sizeof(uint64_t);

			if(serialize(preq,tokens,(uint8_t*)b,size_buffer,&bwritten,token_nr) == -1){
				free(b);
				return 500;
			}

			/*send data to the worker process*/
			if(write(data_sock,b,size_buffer) == -1){ 
				free(b);
				return 500;
			}

			/*
 			 * TODO: refactor the socket comunication so that you read once with 
			 * the size of the next message then you allocate a buffer accordangly so 
			 * you can be eficient
			 *
			 * */
			char read_buffer[MAX_CONT_SZ] = {0};
			int read_res = 0;
			if((read_res = read(data_sock,read_buffer,MAX_CONT_SZ)) == -1){
				free(b);
				return 500;
			}

			if(read_res < 2 || read_res == MAX_CONT_SZ){
				free(b);
				return 500;
			}

			short int error = *(short int*)read_buffer;
			if(read_res < 1023){
				memcpy(cont->cnt_st,&read_buffer[2],strlen(&read_buffer[2]));
			}else{
				/*Maybe allocate memory*/
				fprintf(stderr,"code refactor needed, %s:%d.\n",__FILE__,__LINE__);
				free(b);
				return 500;
			}

			/*cont is already Zeroed, there is no need to */
			cont->size = strlen(cont->cnt_st);
			free(b);
			if(error == 0)
				return 201;
			else
				return 400;
		}
		case NEW_SORD:
		case UPDATE_SORD:
		{
			if(tokens[0].size * 2 + 1 > token_nr) return 400; 
			char **allowed = (char**)NEW_ORD_FIELDS ;
			/*check the keys*/
			int need_mem = 0;
			int seen[MAX_KEY_ALLOWED] = {0};
			for(int m = 1; m < token_nr; m++){
				if(tokens[m].type == ARRAY_JS){
					while( m + 1 < token_nr &&
						tokens[m+1].type == OBJECT_JS){
						/*each array element is precedet from its type*/
						need_mem++; 
						int r = 0;
						m++;
						if((r = check_key_in_object(allowed,preq,&tokens[m],&m,seen)) == -1) return -1;
						need_mem += r;
					}
					need_mem += sizeof(uint32_t);
					continue;
				}

				if(tokens[m].type == STRING_JS){
					int idx = key_allowed(allowed,preq,&tokens[m]);
					if(idx == -1) return 400; /*key not allowed*/
					if(idx < 6 && seen[idx]) return 400; /*duplicate key*/
					seen[idx]++;
					need_mem += (tokens[m].end - tokens[m].start) + sizeof(uint8_t) + sizeof(uint16_t);
				}

				if(tokens[m+1].type == OBJECT_JS){
					int r = 0;
					m++;
					if((r = check_key_in_object(allowed,preq,&tokens[m],&m,seen)) == -1) return -1;
					need_mem += r;
				}
			}

			/*DATA IS GOOD*/

			size_t size_buffer = sizeof(uint64_t) + (sizeof(uint16_t) * 2) + need_mem;
			uint8_t *b = malloc(size_buffer);
			if(!b){
				fprintf(stderr,"(%s): malloc() failed, %s:%d.\n",prog,__FILE__,__LINE__);
				return -1;
			}

			size_t bwritten = 0;
			memcpy(&b[bwritten],&resource,sizeof(uint16_t));
			bwritten += sizeof(uint16_t);

			memcpy(&b[bwritten],&size_buffer,sizeof(uint64_t));
			bwritten += sizeof(uint64_t);

			if(serialize(preq,tokens,b,size_buffer,&bwritten,token_nr) == -1){
				free(b);
				return 500;
			}

			/*send data to the worker process*/
			if(write(data_sock,b,size_buffer) == -1){ 
				free(b);
				return 500;
			}

			/*TODO: refactor the socket comunication so that you read once with 
			 * the size of the next message then you allocate a buffer accordangly so 
			 * you can be eficient
			 *
			 * */
			char read_buffer[MAX_CONT_SZ] = {0};
			int read_res = 0;
			if((read_res = read(data_sock,read_buffer,MAX_CONT_SZ)) == -1){
				free(b);
				return 500;
			}

			if(read_res < 2 || read_res == MAX_CONT_SZ){
				free(b);
				return 500;
			}

			short int error = *(short int*)read_buffer;
			if(read_res < 1023){
				memcpy(cont->cnt_st,&read_buffer[2],strlen(&read_buffer[2]));
			}else{
				/*Maybe allocate memory*/
				fprintf(stderr,"code refactor needed, %s:%d.\n",__FILE__,__LINE__);
				free(b);
				return 500;
			}

			/*cont is already Zeroed, 
			 * there is no need to [i] = '\0'*/
			cont->size = strlen(cont->cnt_st);
			free(b);
			if(error == 0)
				return 201;
			else
				return 400;
		}
		case S_ORD:
		{
			break;
		}
		default:
		break;
		}
		break;
	}
	case GET:
	{
		switch(resource){
			case S_ORD_GET:
			case ITEM_GET:
			case S_ORD_CUSTOMER_GET:
			case CUSTOMER_GET:
				{

					/*get the Key from the request*/
					char *p = NULL;
					switch(resource){
						case S_ORD_GET:
							{
								p = req->resource;
								p += strlen(SALES_ORDERS) + 1;
								break;
							}
						case ITEM_GET:
							{
								p = req->resource;
								p += strlen(ITEMS) + 1;
								break;
							}
						case CUSTOMER_GET:
							{
								p = req->resource;
								p += strlen(CUSTOMERS) + 1;
								break;
							}
						case S_ORD_CUSTOMER_GET:
							{
								p = req->resource;
								p += strlen(SALES_NEW_ORDER_CUSTOMERS) + 1;
								break;
							}
						default:
							return -1;
					}
					/*
					 * check for URL encoding 
					 * if the %20 is found, the function will 
					 * change the string in place
					 * */
					check_URL_encoding(p);

					size_t key_size = strlen(p) +sizeof(uint16_t)+2;
					char buffer[key_size];
					memset(buffer,0,key_size);

					uint16_t *b = (uint16_t*)&buffer[0];
					*b = (uint16_t) resource;
					strncpy(&buffer[2],p,key_size - 2);

					if(write(data_sock,buffer,sizeof(buffer)) == -1){
						return -1;
					}

					char *read_buffer = (char*)malloc(EIGHTkib_limit*4);
					if(!read_buffer) return -1;

					/*read data from worker proc*/

					memset(read_buffer,0,EIGHTkib_limit * 4);
					ssize_t bread = 0;
					if((bread = read(data_sock,read_buffer,(EIGHTkib_limit * 4)-1)) == -1){ 
						free(read_buffer);
						return -1;
					}

					if(bread == ((EIGHTkib_limit * 4) - 1)){
						free(read_buffer);
						fprintf(stderr,"code refactor neened %s:%d\n",__FILE__,__LINE__-1);
						return -1;
					}

					if(read_buffer[0] == '\0'){
						free(read_buffer);
						return -1;
					}

					size_t mem_size = strlen(read_buffer) + 1;
					cont->cnt_dy = (char*) malloc(mem_size);
					if(!cont->cnt_dy) {
						free(read_buffer);
						return -1;
					}

					cont->size = mem_size - 1;
					if(snprintf(cont->cnt_dy,mem_size,"%s",read_buffer) == -1) {
						free(read_buffer);
						return -1;
					}
					free(read_buffer);
					return 0;
				}
			case RPT:
				{
					char *p = req->resource; 
					p += strlen(REPORTS) + 1;

					int size = (int)(strlen(p) + sizeof(uint16_t));
					char buffer[size+1];
					memset(buffer,0,size+1);

					uint16_t *b = (uint16_t*)&buffer[0];
					*b = (uint16_t) resource;

					strncpy(&buffer[2],p,size - sizeof(uint16_t));

					if(write(data_sock,buffer,sizeof(buffer)) == -1){
						return -1;
					}

					/* 
					 * THIS MINI PROTOCOL is IMPLEMENTED ONLY HERE
					 * BECAUSE IS THE ONLY PATH THAT NEEDED THIS IMPLEMENTAION
					 * SO FAR
					 * */
					/*TODO: implement a MAX size for report */
					uint32_t size_rb = 0;
					if(read(data_sock,&size_rb,sizeof(uint32_t)) == -1){
						return -1;
					}


					char *read_buffer = (char*)malloc(size_rb+1);
					if(!read_buffer){
						char not_ok = '\000';
						if(write(data_sock,&not_ok,1) == -1){
							return -1;
						}
						return -1;
					}

					memset(read_buffer,0,size_rb+1);

					/*write to work process: I'M READY TO READ*/
					char ok = '\001';
					if(write(data_sock,&ok,1) == -1){
						free(read_buffer);
						char not_ok = '\000';
						if(write(data_sock,&not_ok,1) == -1){
							return -1;
						}
						return -1;
					}

					/*read data from worker proc*/
					ssize_t bread = 0; 
					while(bread < size){
						ssize_t res = read(data_sock,&read_buffer[bread],size_rb - bread);
						if(res <= 0){
							free(read_buffer);
							return -1;
						}
						bread += res;
					}

					if(read_buffer[0] == '\0'){
						free(read_buffer);
						return -1;
					}

					cont->cnt_dy = (char*) malloc(size_rb + 1);
					if(!cont->cnt_dy) {
						free(read_buffer);
						return -1;
					}

					cont->size = size_rb;
					if(snprintf(cont->cnt_dy,size_rb+1,"%s",read_buffer) == -1) {
						free(read_buffer);
						return -1;
					}
					free(read_buffer);
					return 0;
				}
			case ITEM_GET_ALL:
			case CUSTOMER_GET_ALL:
			case S_ORD:
				{		
					/*send data to the worker process*/
					char buffer[3];
					memset(buffer,0,3);
					uint16_t *b = (uint16_t*)&buffer[0];
					switch(resource){
						case S_ORD:
							*b = (uint16_t)S_ORD;
							break;
						case CUSTOMER_GET_ALL:
							*b = (uint16_t)CUSTOMER_GET_ALL;
							break;
						case ITEM_GET_ALL:
							*b = (uint16_t)ITEM_GET_ALL;
							break;
						default:
							return -1;
					}

					if(write(data_sock,buffer,sizeof(buffer)) == -1){
						return -1;
					}

					char *read_buffer = (char*)malloc(EIGHTkib_limit * 4);
					if(!read_buffer) return -1;

					/*read data from worker proc*/

					memset(read_buffer,0,EIGHTkib_limit * 4);
					ssize_t bread = 0;
					if((bread = read(data_sock,read_buffer,(EIGHTkib_limit * 4)-1)) == -1){
						free(read_buffer);
						return -1;
					}

					if(bread == ((EIGHTkib_limit * 4) - 1)){
						free(read_buffer);
						fprintf(stderr,"code refactor neened %s:%d\n",__FILE__,__LINE__-1);
						return -1;
					}

					if(read_buffer[0] == '\0'){ 
						free(read_buffer);
						return -1;
					}

					size_t mem_size = strlen(read_buffer) + 1;
					cont->cnt_dy = (char*) malloc(mem_size);
					if(!cont->cnt_dy) {
						free(read_buffer);
						return -1;
					}

					cont->size = mem_size - 1;
					if(snprintf(cont->cnt_dy,strlen(read_buffer)+1,"%s",read_buffer) == -1) {
						free(cont->cnt_dy);
						free(read_buffer);
						cont->cnt_dy = NULL;
						return -1;
					}

					free(read_buffer);
					return 0;
				}
			default:
				break;
		}
		break;
	}
	default:
	break;	
	}
	return 400;/*if program reach this line, request is wrong*/
}	

static int key_allowed(char **wlist,const char* json, struct Json_token *k)
{
	int k_len = k->end - k->start;
	for(int i = 0; wlist[i];i++){
		if((int)strlen(wlist[i]) == k_len 
				&& memcmp(wlist[i],&json[k->start],k_len) == 0) return i;
	}
	return -1;
}

static int serialize(const char* json, struct Json_token *t, uint8_t *buffer, size_t buf_size,size_t *bwritten,int token_nr)
{
	if((t->size * 2 + 1) == token_nr){
		if(ser_flat_object(json,t,buffer,buf_size,bwritten) == -1) return -1;
		return 0;
	}

	if((*bwritten + sizeof(uint16_t)) > buf_size) return -1;

	memcpy(&buffer[*bwritten], (uint16_t*)&t->size,sizeof(uint16_t));
	*bwritten += sizeof(uint16_t);

	/*we have nested objects*/
	/*start from 1 so we skip the outer object*/
	for(int m = 1; m < token_nr; m++){

		if(t[m].type == OBJECT_JS){
			if(ser_flat_object(json,&t[m],buffer,buf_size,bwritten) == -1) return -1;
			m += t[m].size * 2;
			continue;
		}

		if(t[m].type == ARRAY_JS){
			if(ser_array(json,&t[m],buffer,buf_size,bwritten,&m) == -1) return -1;
			continue;
		}

		if((*bwritten + sizeof(uint8_t)) > buf_size) return -1;
		memcpy(&buffer[*bwritten],(uint8_t*)&t[m+1].type,sizeof(uint16_t));
		*bwritten += sizeof(uint8_t);



		int len = t[m].end - t[m].start;
		if((*bwritten + sizeof(uint16_t)) > buf_size) return -1;
		memcpy(&buffer[*bwritten],(uint16_t*)&len,sizeof(uint16_t));
		*bwritten += sizeof(uint16_t);

		if((size_t)(*bwritten + len)> buf_size) return -1;
		memcpy(&buffer[*bwritten],&json[t[m].start],len);
		*bwritten += len;
	}
	return 0;
}

static int ser_array(const char *json,struct Json_token *t,uint8_t *buffer,size_t buf_size,size_t *bwritten,int *cursor)
{
	struct Json_token *tmp = t + 1;
	int parent = tmp->parent;
	while(tmp && !is_token_empty(tmp) && tmp->parent == parent){

		if((*bwritten + sizeof(uint8_t)) > buf_size) return -1;
		memcpy(&buffer[*bwritten],(uint8_t*)&tmp->type,sizeof(uint16_t));

		*bwritten += sizeof(uint8_t);
		switch(tmp->type){
		case OBJECT_JS: 
			
			if(ser_flat_object(json,tmp,buffer,buf_size,bwritten) == -1) return -1;
			*cursor += (tmp->size * 2 + 1);
			tmp += tmp->size * 2;
			break;
		default:
			uint16_t len = tmp->end - tmp->start;
			if((*bwritten + sizeof(uint16_t)) > buf_size) return -1;
			memcpy(&buffer[*bwritten],(uint16_t*)&len,sizeof(uint16_t));
			*bwritten += sizeof(uint16_t);

			if((*bwritten + len) > buf_size) return -1;

			memcpy(&buffer[*bwritten],&json[tmp->start],len);
			*bwritten += len;
			break;
		}	
		tmp += 1;
		(*cursor)++;
	}

	uint32_t end_array = JSON_END_ARRAY;
	if((*bwritten + sizeof(uint32_t)) > buf_size) return -1;
	memcpy(&buffer[*bwritten],&end_array,sizeof(uint32_t));
	*bwritten += sizeof(uint32_t);
	return 0;
}

static int ser_flat_object(const char *json,struct Json_token *t,uint8_t *buffer,size_t buf_size,size_t *bwritten)
{
	if((*bwritten + sizeof(uint16_t)) > buf_size) return -1;

	memcpy(&buffer[*bwritten], (uint16_t*)&t->size,sizeof(uint16_t));
	*bwritten += sizeof(uint16_t);

	for(int m = 0; m < t->size; m++){
		int k = 1 + m * 2;
		int v = 2 + m * 2;

		/*write type of the value*/
		if((*bwritten + sizeof(uint8_t)) > buf_size) return -1;
		struct Json_token *token = t + v;
		memcpy(&buffer[*bwritten],(uint8_t*)&token->type,sizeof(uint16_t));
		*bwritten += sizeof(uint8_t);

		/*write key*/
		token = t + k;
		int len = token->end - token->start;
		if((*bwritten + sizeof(uint16_t)) > buf_size) return -1;
		memcpy(&buffer[*bwritten],(uint16_t*)&len,sizeof(uint16_t));
		*bwritten += sizeof(uint16_t);

		if((*bwritten + len) > buf_size) return -1;
		memcpy(&buffer[*bwritten],&json[token->start],len);
		*bwritten += len;

		/*write value*/
		token = t + v;
		len = token->end - token->start;
		if((*bwritten +sizeof(uint16_t)) > buf_size) return -1;
		memcpy(&buffer[*bwritten],(uint16_t*)&len,sizeof(uint16_t));
		*bwritten += sizeof(uint16_t);

		if((*bwritten + len) > buf_size) return -1;
		memcpy(&buffer[*bwritten],&json[token->start],len);
		*bwritten += len;
	}

	return 0;
}

static int check_key_in_object(char **allowed,const char *json,struct Json_token *t,int *i,int *seen)
{
	int need_mem = 0;
	int token_nr = t->size * 2;
	for(int m = 0; m < t->size;m++){
		int ki = 1 + m * 2;
		int vi = 2 + m * 2;

		if(vi > token_nr) return -1;
		int idx = key_allowed(allowed,json,&t[ki]);

		if(idx == -1) return -1; /*key not allowed*/
		if(idx < 6 && seen[idx]) return 400; /*duplicate key*/
		seen[idx]++;

		need_mem += (t[ki].end - t[ki].start) + sizeof(uint8_t) + sizeof(uint16_t);
		need_mem += (t[vi].end - t[vi].start) + sizeof(uint8_t) + sizeof(uint16_t);
	}
	*i  += token_nr;  
	return need_mem;
}

#endif
static int check_URL_encoding(char *p)
{
	int sz = (int)strlen(p);
	char clean[sz];
	memset(clean,0,sz);
	int copied = 0;

	char *s = p;
	char *space = NULL;
	while((space = strstr(s,"%20"))){
		*space++ = ' ';
		int where = space - s; 	
		strncpy(&clean[copied],s,where);
		copied += where;
		space += 2;
		s = space;
	}

	if(!copied)
		return 0;

	strncpy(&clean[copied],s,strlen(s));
	strncpy(p,clean,strlen(clean));
	p[strlen(clean)] = '\0';
	return 0;
}

