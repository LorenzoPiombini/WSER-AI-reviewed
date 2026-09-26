#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/random.h>
#include <sys/un.h>
#include <netdb.h>
#include <errno.h>
#include <ifaddrs.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <fcntl.h>
#include <assert.h>
#include "network.h"       
#include "response.h"       
#include "request.h"       
#include "monitor.h"       

char cache_id[] = "wser";
SSL_CTX *ctx = NULL;
SSL *ssl_client = NULL;

#define USE_HTTPS 0
#define DNS_SERVER "8.8.8.8"

static char prog[] = "wser";
static int SSL_client_setup(SSL_CTX **ctx);
static int handle_client_IO(SSL *ssl, int ret);
static int wait_for_activity(SSL *ssl, int w_r);
static long read_hex_for_transfer_encoding(char *, long *);
static void clean_CRNL(char *str);
static void clean_garbage(char *str);
static void debugf(char *fmt);
static void format_domain_for_query(char *domain, uint8_t *formatted_domain);
static char *convert_query_format_domain_to_string(uint8_t* formatted_domain);
#define LISTEN_BACKLOG 50
#define MAX_BUF_SIZE 2048

struct Connection_data cds[MAX_CON_DAT_ARR] = {0};

int init_SSL(SSL_CTX **ctx){
	long opts;

	*ctx = SSL_CTX_new(TLS_server_method());
	if(!(*ctx)) {
		fprintf(stderr,"failed to create SSL context");
		return -1;
	}


	if(!SSL_CTX_set_min_proto_version(*ctx,TLS1_2_VERSION)) {
		fprintf(stderr,"failed to set minimum TLS version\n");
		SSL_CTX_free(*ctx);
		return -1;
	}

	/*
	 * setting the option for the SSL context
	 *
	 * for documentation on what this option are please see
	 * openSSL documentaion at 
	 * https://docs.openssl.org/master/man7/ossl-guide-tls-server-block/
	 * or 
	 * https://github.com/openssl/openssl/blob/master/demos/guide/tls-server-block.c 
	 **/

	opts = SSL_OP_IGNORE_UNEXPECTED_EOF;
	opts |= SSL_OP_NO_RENEGOTIATION;
	opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;

	/*apply the selction options */
	SSL_CTX_set_options(*ctx, opts);

	/*NOTE: this will always change! depends on the implementation*/
	if(SSL_CTX_use_certificate_chain_file(*ctx,"/home/lpiombini/local_cert/server.crt") <= 0 ) {
		fprintf(stderr,"error use certificate.\n");
		return -1;
	}

	if(SSL_CTX_use_PrivateKey_file(*ctx, "/home/lpiombini/local_cert/server.key",SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr,"error use privatekey ");
		return -1;
	}

	SSL_CTX_set_session_id_context(*ctx,(void*)cache_id,sizeof(cache_id));
	SSL_CTX_set_session_cache_mode(*ctx,SSL_SESS_CACHE_SERVER);
	SSL_CTX_sess_set_cache_size(*ctx, 1024);
	SSL_CTX_set_timeout(*ctx,3600);
	SSL_CTX_set_verify(*ctx,SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_cipher_list(*ctx,"ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!3DES");
	SSL_CTX_set_ciphersuites(*ctx,"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
	return 0;
}

int listen_port_80(uint16_t *port)
{

	int try = 10;/* number of tryes in case of error*/
	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(*port); 
	addr.sin_addr.s_addr = INADDR_ANY;
	errno = 0;
	int sock_fd = socket(AF_INET,SOCK_STREAM | SOCK_NONBLOCK,0);
	if(sock_fd == -1) return -1;
		

sock_setup:

       	if(bind(sock_fd, (struct sockaddr *)&addr,sizeof(addr)) == -1){
		close(sock_fd);
		if(*port != 8080)
			*port = 8080;
		else
			(*port)++;

		while(errno == EACCES){
			if(try == 0) break;
			errno = 0;
			addr.sin_port = htons(*port); 
			sock_fd = socket(AF_INET,SOCK_STREAM | SOCK_NONBLOCK,0);
			try--;
		}
		
		if(errno == 0) goto sock_setup;
		return -1;
	}

	if(listen(sock_fd,LISTEN_BACKLOG) == -1){
		close(sock_fd);
		return -1;
	}

	return sock_fd;
}

static int unix_address(struct sockaddr_un *addr, const char *path)
{
    if(!path || !*path){ errno = EINVAL; return -1; }
    if(strlen(path) >= sizeof(addr->sun_path)){ errno = ENAMETOOLONG; return -1; }
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    memcpy(addr->sun_path, path, strlen(path) + 1);
    return 0;
}

static int close_failed_socket(int fd)
{
    int error = errno;
    close(fd);
    errno = error;
    return -1;
}

int connect_UNIX_socket(int opt, char *sock_path)
{
    struct sockaddr_un addr;
    if(unix_address(&addr, sock_path)) return -1;
    int flags = SOCK_SEQPACKET | SOCK_CLOEXEC;
    if(opt == SOCK_NONBLOCK) flags |= SOCK_NONBLOCK;
    int fd = socket(AF_UNIX, flags, 0);
    if(fd < 0) return -1;
    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        if(opt == SOCK_NONBLOCK && errno == EINPROGRESS) return fd;
        return close_failed_socket(fd);
    }
    return fd;
}

int listen_UNIX_socket(int opt, char *sock_path)
{
    struct sockaddr_un addr;
    if(unix_address(&addr, sock_path)) return -1;
    struct stat st;
    if(lstat(sock_path, &st) == 0){
        /* Never remove an unrelated regular file or follow a symlink. */
        if(!S_ISSOCK(st.st_mode)){ errno = EEXIST; return -1; }
        if(unlink(sock_path)) return -1;
    } else if(errno != ENOENT) return -1;
    int flags = SOCK_SEQPACKET | SOCK_CLOEXEC;
    if(opt == SOCK_NONBLOCK) flags |= SOCK_NONBLOCK;
    int fd = socket(AF_UNIX, flags, 0);
    if(fd < 0) return -1;
    if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return close_failed_socket(fd);
    if(listen(fd, 20) < 0){
        int error = errno;
        unlink(sock_path);
        errno = error;
        return close_failed_socket(fd);
    }
    return fd;
}

static char *convert_query_format_domain_to_string(uint8_t* formatted_domain)
{
	char *p = formatted_domain;	
	char *dom = malloc(255);
	if(!dom)
		return NULL;

	char *start = &dom[0];
	for(;*p;p++){
		if(p == (char*)&formatted_domain[0]){
			continue;
		}else if((int)*p < 0x41){
			*dom++ = '.';
			continue;
		}
		*dom++ = *p;
	}
	return start;
}
static void format_domain_for_query(char *domain, uint8_t *formatted_domain)
{
	size_t s = strlen(domain);
	char cpy[s+1];
	memset(cpy,0,s+1);
	strncpy(cpy,domain,s+1);

	uint8_t buf[255] = {0};
	
	int i = 0, j = 1, x = 0;
	for(char *p = &cpy[0]; *p;p++,i++){
		if(*p == '.'){
			buf[x] = (uint8_t)i;
			x = j;
			j++;
			i = -1;
			continue;
		}
		buf[j] = (uint8_t)*p;
		j++;
	}
	buf[x] = (uint8_t)i;
	memcpy(formatted_domain,buf,255);
}
uint16_t convert_string_to_type(char *type){

	if(strlen(type) == 1 && (strncmp(type,"A",1) == 0))
		return (uint16_t)A;
	if(strlen(type) == 2 && (strncmp(type,"NS",2) == 0))
		return (uint16_t)NS;
	if(strlen(type) == 5 && (strncmp(type,"CNAME",5) == 0))
		return (uint16_t)CNAME;
	if(strlen(type) == 3 && (strncmp(type,"SOA",3) == 0))
		return (uint16_t)CNAME;
	if(strlen(type) == 2 && (strncmp(type,"MB",2) == 0))
		return (uint16_t)MB;
	if(strlen(type) == 2 && (strncmp(type,"MG",2) == 0))
		return (uint16_t)MG;
	if(strlen(type) == 2 && (strncmp(type,"MR",2) == 0))
		return (uint16_t)MR;
	if(strlen(type) == 2 && (strncmp(type,"MX",2) == 0))
		return (uint16_t)MX;
	if(strlen(type) == 3 && (strncmp(type,"TXT",3) == 0))
		return (uint16_t)TXT;
	if(strlen(type) == 5 && (strncmp(type,"HINFO",5) == 0))
		return (uint16_t)HINFO;
	if(strlen(type) == 5 && (strncmp(type,"MINFO",5) == 0))
		return (uint16_t)MINFO;

	return 0;
}
int DNS_query(char *domain, uint16_t type)
{

	/*PREPARE THE DNS query*/

	struct DNS_header header = {0};
	if(getrandom(&header.id,sizeof(uint16_t),0) == -1)
		return -1;

	header.id = htons(header.id);
	SET_RD(header.fields);
	SET_Z(header.fields);
	header.fields = htons(header.fields);
	header.qdcount = htons((uint16_t)1);

	struct DNS_question question= {0};
	format_domain_for_query(domain,question.qname);
	question.qtype = htons(type);
	question.qclass = htons((uint16_t)1); /*CLASS IN*/

	uint8_t b[512] = {0};
	int qname_sz =(int) strlen((char*)question.qname);
	
	memcpy(b,&header,sizeof(header));
	memcpy(&b[sizeof(header)],question.qname,qname_sz+1);/*+1 is to respect the format of QNAME*/
	memcpy(&b[sizeof(header)+qname_sz+1],&question.qtype,sizeof(uint16_t));
	memcpy(&b[sizeof(header)+qname_sz+1+sizeof(uint16_t)],&question.qclass,sizeof(uint16_t));

	/*create UDP socket*/
	int udp_sock = socket(AF_INET,SOCK_DGRAM,0);
	if(udp_sock == -1)
		return -1;

	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53); /*port number as per RFC 1035*/ 
	addr.sin_addr.s_addr = inet_addr(DNS_SERVER) ;
	uint16_t size_of_query =(uint16_t) (sizeof(header)+qname_sz+1+(2*sizeof(uint16_t)));

	if(sendto(udp_sock,b,size_of_query,0,(struct sockaddr*)&addr,(socklen_t)sizeof(addr)) == -1){
		close(udp_sock);
		return -1;
	}
	
	uint8_t raw_response[512] = {0};
	int addr_size = (int)sizeof(addr);
	if(recvfrom(udp_sock,raw_response,512,0,(struct sockaddr*)&addr,(socklen_t*)&addr_size) == -1){
		close(udp_sock);
		return -1;
	}

	/*parse the response*/
	int bread = 0;
	struct DNS_record res_r = {0};
	struct DNS_question res_q = {0};
	struct DNS_header res_h = *(struct DNS_header*)raw_response;
	if(res_h.id != header.id)
		return -1;

	res_h.fields = ntohs(res_h.fields);
	uint8_t * big_raw_response = NULL;
	if(GET_TC(res_h.fields) == (uint8_t)1){
		printf("data is truncated\n");
		close(udp_sock);
		udp_sock = -1;
		
		/*create TCP socket*/
		int tcp_sock = socket(AF_INET,SOCK_STREAM,0);
		if(tcp_sock == -1)
			return -1;
	
		if(connect(tcp_sock,(struct sockaddr*)&addr,(socklen_t)sizeof(addr)) == -1)
			return -1;

		uint8_t b_for_tcp[size_of_query+2];
		memset(b_for_tcp,0,size_of_query+2);
		uint16_t c = htons(size_of_query);
		memcpy(b_for_tcp,&c,sizeof(uint16_t));
		memcpy(&b_for_tcp[sizeof(uint16_t)],b,size_of_query);
		 
		big_raw_response = malloc(1024*4);
		if(!big_raw_response)
			return -1;
		ssize_t br = 0, bw = 0;
		if((bw = write(tcp_sock,b_for_tcp,size_of_query+2))== -1)
			return -1;
		if((br = read(tcp_sock,big_raw_response,1024*4)) == -1)
			return -1;
		uint16_t  size = ntohs(*(uint16_t*)big_raw_response);
	

		close(tcp_sock);
		memset(&res_h,0,sizeof(struct DNS_header));
		res_h = *(struct DNS_header*)&big_raw_response[2];
		if(res_h.id != header.id){
			free(big_raw_response);
			return -1;
		}	

		bread += sizeof(uint16_t);
		if(GET_TC(res_h.fields) == (uint8_t)1){
			printf("data is truncated even with TCP\n");
			free(big_raw_response);
			return -1;
		}
	}

	if(res_h.ancount == 0){
		printf("no record in the answer\n");
		if(big_raw_response)
			free(big_raw_response);
		else
			close(udp_sock);
		return -1;
	}

	if((uint16_t)GET_QR(res_h.fields) != QR){
		if(big_raw_response)
			free(big_raw_response);
		else
			close(udp_sock);
		return -1;
	}

	printf("QR -> response.\n");
	printf("OPCODE -> %s - %s.\n",((uint8_t)GET_OPCODE(res_h.fields)) == 0 ? "QUERY" : "ERROR!",
				(uint8_t)GET_RCODE(res_h.fields) == (uint8_t)NO_ERROR ? "NOERROR":"ERROR!");

	bread += (int)sizeof(struct DNS_header);
	memcpy(res_q.qname,
			!big_raw_response ? &raw_response[bread] : &big_raw_response[bread],qname_sz+1);
	bread += qname_sz +1;
	
	res_q.qtype = *(uint16_t*) (!big_raw_response ? &raw_response[bread] : &big_raw_response[bread]);
	bread += (int)sizeof(uint16_t);
	


	res_q.qclass = *(uint16_t*) (!big_raw_response ? &raw_response[bread] : &big_raw_response[bread]);
	bread += (int)sizeof(uint16_t);
	
	
	/*RESOURCE RECORD*/
	uint16_t offset = 0;
	uint16_t p = ntohs(*(uint16_t*) (!big_raw_response ? &raw_response[bread] : &big_raw_response[bread]));
	
	if(IS_A_POINTER(p)){
		/*get the offset of the domain in the message*/
		offset = p & 0x0FFF; 
		bread += sizeof(uint16_t);	
		uint8_t name[qname_sz+1];
		memset(name,0,qname_sz+1);

		memcpy(name,!big_raw_response ? &raw_response[offset] : &big_raw_response[bread],qname_sz+1);
		char *dom_converted = convert_query_format_domain_to_string(name);
		if(!dom_converted){
			if(big_raw_response)
				free(big_raw_response);
			else
				close(udp_sock);
			return -1;
		}

		printf("domain -> %s\n",dom_converted);
		free(dom_converted);
	}

	res_r.type = *(uint16_t*)(!big_raw_response ? &raw_response[bread] : &big_raw_response[bread]);
	bread += sizeof(uint16_t);	
	res_r.class = *(uint16_t*)(!big_raw_response ? &raw_response[bread] : &big_raw_response[bread]);
	bread += sizeof(uint16_t);	

	if(res_r.type != question.qtype || res_r.class != question.qclass){
		if(big_raw_response)
			free(big_raw_response);
		else
			close(udp_sock);
		return -1;
	}

	res_r.ttl = *(uint32_t*) (!big_raw_response ? &raw_response[bread] : &big_raw_response[bread]);
	bread += sizeof(uint32_t);	
	res_r.rdlength = ntohs(*(uint16_t*)(!big_raw_response ? &raw_response[bread] : &big_raw_response[bread]));
	bread += sizeof(uint16_t);
	
	uint32_t ip_address = *(uint32_t*) (!big_raw_response ? &raw_response[bread] :&big_raw_response[bread]);

	// 32 bit integer 
	// 0000 0000 0000 0000 0000 0000 0000 0000 
	// i did not swap from big endian to little endian that is why
	// the printf statement is reversed
	uint8_t f = (uint8_t)((ip_address & 0xFF000000) >> 24);
	uint8_t s = (uint8_t)((ip_address & 0x00FF0000) >> 16);
	uint8_t t = (uint8_t)((ip_address & 0x0000FF00) >> 8);
	uint8_t fr = (uint8_t)(ip_address & 0x000000FF);
	printf("ip4 address -> %u.%u.%u.%u\n",fr,t,s,f);

	if(big_raw_response)
		free(big_raw_response);
	else
		close(udp_sock);
	return 0;
}

int write_cli_SSL(int cli_sock, struct Response *res, struct Connection_data *cd)
{
    int i;
    for(i = 0; i < MAX_CON_DAT_ARR; ++i) if(cd[i].fd == cli_sock) break;
    if(i == MAX_CON_DAT_ARR || !cd[i].ssl) return -1;
    struct Connection_data *c = &cd[i];
    if(!c->buf){
        if(!res) return -1;
        size_t h = strlen(res->header_str);
        if(res->body.size > SIZE_MAX - h) return -1;
        c->buf_size = h + res->body.size;
        c->buf_sent = 0;
        c->buf = malloc(c->buf_size ? c->buf_size : 1);
        if(!c->buf) return -1;
        memcpy(c->buf, res->header_str, h);
        memcpy(c->buf + h, res->body.d_cont ? res->body.d_cont : res->body.content, res->body.size);
    }
    while(c->buf_sent < c->buf_size){
        size_t n = 0;
        ERR_clear_error();
        int r = SSL_write_ex(c->ssl, c->buf + c->buf_sent, c->buf_size - c->buf_sent, &n);
        if(r == 1){ c->buf_sent += n; continue; }
        int err = SSL_get_error(c->ssl, r);
        if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
            c->retry_read = NULL;
            c->retry_handshake = NULL;
            c->retry_write = SSL_write_ex;
            if(modify_monitor_event(cli_sock, err == SSL_ERROR_WANT_WRITE ? EPOLLOUT : EPOLLIN) == -1) return -1;
            return SSL_WRITE_E;
        }
        c->retry_write = NULL;
        free(c->buf);
        c->buf = NULL;
        return -1;
    }
    c->retry_write = NULL;
    free(c->buf);
    c->buf = NULL;
    c->buf_size = c->buf_sent = 0;
    /* Send close_notify without spinning on a nonblocking peer. */
    SSL_shutdown(c->ssl);
    return 0;
}

int write_cli_sock(int cli_sock, struct Response *res)
{
    size_t header_size = strlen(res->header_str);
    if(res->body.size > SIZE_MAX - header_size) return -1;
    size_t total = header_size + res->body.size;
    if(res->sent > total) return -1;
    while(res->sent < total){
        const char *p;
        size_t remaining;
        if(res->sent < header_size){
            p = res->header_str + res->sent;
            remaining = header_size - res->sent;
        } else {
            size_t offset = res->sent - header_size;
            p = (res->body.d_cont ? res->body.d_cont : res->body.content) + offset;
            remaining = res->body.size - offset;
        }
        ssize_t n = send(cli_sock, p, remaining, MSG_NOSIGNAL);
        if(n > 0){ res->sent += (size_t)n; continue; }
        if(n < 0 && errno == EINTR) continue;
        if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return EAGAIN;
        return -1;
    }
    return 0;
}


void clean_connecion_data(struct Connection_data *cd, int sock)
{
	if(sock != -1){
				
		int i;
		for(i = 0; i < MAX_CON_DAT_ARR; i++){
			if(cd[i].fd != sock) continue;

			cd[i].fd = -1;
			if(cd[i].ssl){
				SSL_free(cd[i].ssl);
				cd[i].ssl = NULL;
			}

			cd[i].retry_read = NULL;
			cd[i].retry_handshake = NULL;
			cd[i].retry_write = NULL;
			cd[i].close_notify = NULL;
			clear_response(&cd[i].res);
			if(cd[i].buf){
				free(cd[i].buf);
				cd[i].buf = NULL;
			}
			return;
		}

		return;
	}

	int i;
	for(i = 0; i < MAX_CON_DAT_ARR; i++){
		
		cd[i].fd = -1;
		if(cd[i].ssl){
			SSL_free(cd[i].ssl);
			cd[i].ssl = NULL;
		}

		cd[i].retry_read = NULL;
		cd[i].retry_handshake = NULL;
		cd[i].retry_write = NULL;
		cd[i].close_notify = NULL;
		clear_response(&cd[i].res);
		if(cd[i].buf){
			free(cd[i].buf);
			cd[i].buf = NULL;
		}
	}
}

int read_cli_sock_SSL(int cli_sock, struct Request *req, struct Connection_data *cd)
{
    int i;
    for(i = 0; i < MAX_CON_DAT_ARR; ++i) if(cd[i].fd == cli_sock) break;
    if(i == MAX_CON_DAT_ARR || !cd[i].ssl) return NO_CON_DATA;
    struct Connection_data *c = &cd[i];
    if(!SSL_is_init_finished(c->ssl)){
        ERR_clear_error();
        int r = SSL_accept(c->ssl);
        if(r != 1){
            int err = SSL_get_error(c->ssl, r);
            if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) return -1;
            c->retry_handshake = SSL_accept;
            if(modify_monitor_event(cli_sock, err == SSL_ERROR_WANT_WRITE ? EPOLLOUT : EPOLLIN) == -1) return -1;
            return HANDSHAKE;
        }
        c->retry_handshake = NULL;
    }
    for(;;){
        int status = handle_request(req);
        if(status != BDY_MISS){ c->retry_read = NULL; return status; }
        size_t cap = req->d_req ? req->capacity : sizeof(req->req);
        if(req->size < 0 || (size_t)req->size > cap) return BAD_REQ;
        if((size_t)req->size == cap){
            if(cap >= MAX_REQUEST_SIZE) return BAD_REQ;
            if(set_up_request(cap, req)) return -1;
            cap = req->capacity;
        }
        char *raw = req->d_req ? req->d_req : req->req;
        size_t n = 0;
        ERR_clear_error();
        int r = SSL_read_ex(c->ssl, raw + req->size, cap - (size_t)req->size, &n);
        if(r == 1){ req->size += n; continue; }
        int err = SSL_get_error(c->ssl, r);
        if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) return -1;
        c->retry_read = SSL_read_ex;
        if(modify_monitor_event(cli_sock, err == SSL_ERROR_WANT_WRITE ? EPOLLOUT : EPOLLIN) == -1) return -1;
        return SSL_READ_E;
    }
}

int read_cli_sock(int cli_sock, struct Request *req)
{
    for(;;){
        int status = handle_request(req);
        if(status != BDY_MISS) return status;
        size_t cap = req->d_req ? req->capacity : sizeof(req->req);
        if(req->size < 0 || (size_t)req->size > cap) return BAD_REQ;
        if((size_t)req->size == cap){
            if(cap >= MAX_REQUEST_SIZE) return BAD_REQ;
            if(set_up_request(cap, req)) return -1;
            cap = req->capacity;
        }
        char *raw = req->d_req ? req->d_req : req->req;
        ssize_t n = recv(cli_sock, raw + req->size, cap - (size_t)req->size, 0);
        if(n > 0){ req->size += n; continue; }
        if(n == 0) return BAD_REQ;
        if(errno == EINTR) continue;
        if(errno == EAGAIN || errno == EWOULDBLOCK) return EAGAIN;
        return -1;
    }
}

int wait_for_connections_SSL(int sock_fd,int *cli_sock)
{
	struct sockaddr cli_info;
	socklen_t len = sizeof(cli_info);
	errno = 0;

	if((*cli_sock = accept4(sock_fd,&cli_info,&len,SOCK_NONBLOCK)) == -1){
		if(errno == EAGAIN || errno == EWOULDBLOCK) {
			return errno;
		}
		return -1;
	}

	return 0;
}

int wait_for_connections(int sock_fd,int *cli_sock, struct Request *req,int mode)
{
	struct sockaddr cli_info;
	socklen_t len = sizeof(cli_info);
	errno = 0;

	if((*cli_sock = accept4(sock_fd,&cli_info,&len,SOCK_NONBLOCK)) == -1){
		if(errno == EAGAIN || errno == EWOULDBLOCK) {
			return errno;
		}
		return -1;
	}

	if( mode != MULTI_PROC){
		int e = 0;
		if(( e = read_cli_sock(*cli_sock,req)) == -1){
			fprintf(stderr,"(%s): cannot read data from socket",prog);
			return -1;
		}

		if( e == EAGAIN || e == EWOULDBLOCK || e == BAD_REQ) return e;

	}
	return 0;	
}

void stop_listening(int sock_fd)
{
	close(sock_fd);
}

void SSL_client_close(){
	SSL_CTX_free(ctx);
	SSL_free(ssl_client);
}
int SSL_client_config(){
	if(SSL_client_setup(&ctx) != 0){
		if(ctx)
			SSL_CTX_free(ctx);

		return -1;
	}
	if((ssl_client = SSL_new(ctx)) == NULL){
		SSL_CTX_free(ctx);
		return -1;
	}
	return 0;
}

int perform_http_request(char *URL, char *req, char **body)
{
	/*process the url*/
	struct Url url = {0};
	if(parse_URL(URL,&url) == -1) return -1;	

	int secure = 0;
	if(!ssl_client){
		if(strncmp(url.protocol,"https",5) == 0)
			secure = 1;
	} else{
		secure = 1;
	}

	if(secure){
		if(!ssl_client){
			if(SSL_client_setup(&ctx) != 0){
				if(ctx)
					SSL_CTX_free(ctx);

				return -1;
			}
			if((ssl_client = SSL_new(ctx)) == NULL){
				SSL_CTX_free(ctx);
				return -1;
			}
		}else{
			SSL_clear(ssl_client);
		}
	}

	/*get addr info*/
	int rsl = 0;
	struct addrinfo hints = {0};
	struct addrinfo *result;

	hints.ai_family = AF_UNSPEC; /* allow IPv4 and IPv6*/
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if((rsl = getaddrinfo(url.host,url.protocol, &hints,&result)) != 0){
		fprintf(stderr, "(%s): getaddrinfo: %s\n",prog, gai_strerror(rsl));
		return -1;
	}

	int  sock_fd = -1;
	struct addrinfo *rp;
	for( rp = result; rp != NULL; rp = rp->ai_next){
		if((sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1) continue;
		if(connect(sock_fd,rp->ai_addr,rp->ai_addrlen) != -1) break;
		close(sock_fd);
	}

	freeaddrinfo(result);

	if(fcntl(sock_fd,F_SETFD,O_NONBLOCK) == -1){
		close(sock_fd);
		return -1;
	}

	if(!rp) {
		fprintf(stderr,"(%s): could not connect to '%s'.\n",prog,URL);
		return -1;
	}

	if(ssl_client){
		if(!SSL_set_fd(ssl_client,sock_fd)){
			close(sock_fd);
			return -1;
		}

		if(!SSL_set_tlsext_host_name(ssl_client,url.host)){
			close(sock_fd);
			return -1;
		}

		if(!SSL_set1_host(ssl_client,url.host)){
			close(sock_fd);
			return -1;
		}

		int ret = 0;
		while((ret = SSL_connect(ssl_client)) != 1){
			int r = handle_client_IO(ssl_client,ret); 
			if(r == 1)
				continue;
			else if( r == 0)
				break;

			close(sock_fd);
			return -1;
		}
	}

	size_t bread = 0;
	char buff[MAX_BUF_SIZE] = {0};
	char *pbuf = &buff[0];
	char *all_data_from_the_response = NULL;
	if(ssl_client){
		/*send the request*/
		size_t bwritten = 0;
		while(!SSL_write_ex(ssl_client,req,strlen(req),&bwritten)){
			if(handle_client_IO(ssl_client,0) == 1)
				continue;

			close(sock_fd);
			return -1;
		}

		/*read the response*/
		size_t first_alloc = 0;
		long h_end = 0;
		int index = 0;
		int eof = 0;
		int tf = 0;
		int hf = 0;
		long ix = 0;
		size_t sz = 0;
		int cl = 0;
		size_t byte_to_read = MAX_BUF_SIZE-1;
		while((!eof && !SSL_read_ex(ssl_client,&pbuf[index],byte_to_read,&bread)) || (bread <= byte_to_read) || tf){
			
			if(!hf){
				if((ix = find_headers_end(pbuf,strlen(pbuf))) == -1){
					/*response header is not complete */
					index = strlen(pbuf);
					if((size_t)index >= byte_to_read){
						if(first_alloc){
							byte_to_read =  first_alloc - index - 1;
							assert(byte_to_read < sz);
							assert(byte_to_read > 0);
							assert((sz - strlen(pbuf)) > byte_to_read);
						}else{
							if(&buff[0] == pbuf){
								pbuf = calloc(MAX_BUF_SIZE*2,sizeof(char));
								if(!pbuf){
									/*TODO: handle*/
								}
								first_alloc += MAX_BUF_SIZE*2;
								memcpy(pbuf,buff,strlen(buff));
								index = strlen(pbuf);
								byte_to_read = first_alloc - index - 1;
								continue;
							}	
						}
					}else{
						byte_to_read -= index;
						//assert(byte_to_read < sz);
						assert(byte_to_read > 0);
						//assert((sz - strlen(pbuf)) > byte_to_read);
					}
					continue;
				}
				hf = 1;
			}

			/*HERE YOU HAVE ALL THE HEADER*/
			if(!tf){
				/*check for transfer encoding */
				if(pbuf[0] == '{'){
					if(strstr(pbuf,"\"message\":")){
						break;
					}
				}
				if(strstr(pbuf,"transfer-encoding") || strstr(pbuf,"Transfer-Encoding")){
					tf = 1;
					sz = read_hex_for_transfer_encoding(&pbuf[ix], &ix); 
					if(sz == 0)
						break;

					/*allocate memory for the chunk*/
					if(&buff[0] == pbuf){
						/*Discard the header -- keep the body --*/
						size_t len = strlen(&buff[ix]);
						if(sz < len){
							sz *= 2;	
						}

						pbuf = calloc(sz+1,sizeof(char));	
						if(!pbuf){
							close(sock_fd);
							return -1;
						}


						byte_to_read = sz - len -1;
						memcpy(pbuf,&buff[ix],len);
						assert(byte_to_read < sz);
						assert(byte_to_read > 0);
						first_alloc = sz;
						index = strlen(pbuf);
						continue;
					}else{
						/*Discard the header -- keep the body --*/
						/* 100 bytes of extra buffer*/
						char *new= calloc(sz += 100,sizeof(char));
						if(!pbuf){
							close(sock_fd);
							return -1;
						}
						memcpy(new,&pbuf[ix],strlen(&pbuf[ix]));
						free(pbuf);
						pbuf = new;
						index = strlen(pbuf);
						byte_to_read = sz - strlen(&pbuf[ix]) - 1;
						assert(byte_to_read < sz);
						assert(byte_to_read > 0);
						first_alloc = sz;
						continue;
					}
				}

				if(bread == byte_to_read && !hf){
					if(pbuf == &buff[0]){
						index = strlen(buff);	
						pbuf = calloc(MAX_BUF_SIZE*2,sizeof(char));  
						if(!pbuf){
							close(sock_fd);
							return -1;
						}
						first_alloc = (MAX_BUF_SIZE * 2);
						memcpy(pbuf,buff,strlen(buff));
						byte_to_read = MAX_BUF_SIZE-1;
						sz = first_alloc;
						assert((sz - strlen(pbuf)) > byte_to_read);
						continue;
					}

					char *new = realloc(pbuf,first_alloc += MAX_BUF_SIZE);
					if(!new){
						close(sock_fd);
						return -1;
					}
					pbuf = new;
					index = strlen(pbuf);
					byte_to_read = first_alloc - index - 1;
					continue;
				}

				/*header is compleate*/
				char *cont_lt = NULL;
				if((cont_lt = strstr(pbuf,"Content-Length"))){
					cl = 1;
					cont_lt += strlen("Content-Length: ");
					char *end = strstr(cont_lt,"\r");
					assert(end != NULL);
					long lt = end - cont_lt;
					char num[lt+1];
					memset(num,0,lt+1);
					strncpy(num,cont_lt,lt);
					errno = 0;
					long n = strtol(num,NULL,10);
					if(errno == EINVAL){
						/*Handle this*/	
					}

					if((int)strlen(&pbuf[ix]) == n){
						break;
					}else if((int)strlen(&pbuf[ix]) < n){
						char *temp = calloc(n+1,sizeof(char));
						if(!temp){
							/*handle*/
						}

						memcpy(temp,&pbuf[ix],strlen(&pbuf[ix]));
						if(&buff[0] != pbuf){
							free(pbuf);
							pbuf = NULL;
						}

						pbuf = temp;
						first_alloc = n;
						index = strlen(pbuf);
						/* we already have part of the body */
						byte_to_read = n - index;
						continue;
					}

					/*TODO: is this necessery?*/

					if(&buff[0] != pbuf){
						free(pbuf);
						pbuf = NULL;
					}

					pbuf = calloc(n+1,sizeof(char));
					if(!pbuf){
						/*handle*/

					}
					first_alloc = n;
					index = 0;
					byte_to_read = n;
					continue;
				}
				if(cl){
					if(byte_to_read - bread > 0){
						index = strlen(pbuf);
						byte_to_read = byte_to_read - bread;
						continue;
					}
					cl = 0;
					break;
				}
			}else{
				//	debugf(pbuf);
				if(!strstr(pbuf,"\r\n0\r\n")){
					char *CRNL = strstr(pbuf,"\r\n");
					if(CRNL){
						/*make sure you have the all size data*/
						*CRNL = ' ';
						if(!strstr(CRNL,"\r\n")){
							*CRNL = '\r';
							index = strlen(pbuf);		
							byte_to_read = sz - index -1;
							assert(byte_to_read < sz);
							if(byte_to_read == 0){
								char *f = strstr(CRNL,"\r\n");
								*f = '\0';
								long sn = strtol(pbuf,NULL,16);
								char *new = realloc(pbuf,sz+sn);
								if(!new){
									close(sock_fd);
									return -1;
								}
								pbuf = new;
								sz += sn;
								index = strlen(pbuf);		
								byte_to_read = sz - index -1;
								assert(byte_to_read < sz);
								assert(byte_to_read > 0);
								assert((sz - strlen(pbuf)) > byte_to_read);
								continue;
							}

							if((size_t)index > sz){
								/*realloc*/
								printf("you are missing a realloc\n");
							}
							continue;
						}
						/*we have all the chunked size info*/
						*CRNL = '\r';
						CRNL += 2;
						long hinx =(int) (CRNL - pbuf);
						long sz_to_realloc = read_hex_for_transfer_encoding(CRNL,&hinx);		
						if(sz_to_realloc == 0)
							break;

						char *new = realloc(pbuf,sz += sz_to_realloc);
						if(!new){
							close(sock_fd);
							break;
						}
						pbuf  = new;
						memset(&pbuf[strlen(pbuf)],0,sz- strlen(pbuf));
						index = strlen(pbuf); 
						byte_to_read = sz_to_realloc-1;
						assert(byte_to_read < sz);
						assert(byte_to_read > 0);
						assert((sz - strlen(pbuf)) > byte_to_read);
						clean_CRNL(pbuf);
						continue;
					}
					index = strlen(pbuf);		
					byte_to_read = sz - index -1;
					if(byte_to_read == 0 && first_alloc > 0){
						/*realloc*/
						char *new = realloc(pbuf,sz += MAX_BUF_SIZE);
						if(!new){
							close(sock_fd);
							break;
						}
						pbuf = new;
						memset(&pbuf[strlen(pbuf)],0,sz - strlen(pbuf));
						byte_to_read = sz - strlen(pbuf) - 1;		
						assert(byte_to_read < sz);
						assert(byte_to_read > 0);
						assert((sz - strlen(pbuf)) > byte_to_read);
					}
					continue;
				}
				/*here you have all the body*/
				tf = 0;
				long l = 0;
				if(&buff[0] == pbuf){
					h_end = find_headers_end(buff, strlen(buff));
					read_hex_for_transfer_encoding(&buff[h_end],&h_end);
					l = strlen(&buff[h_end]) + strlen(pbuf) +1;

				}else{
					l =  strlen(pbuf) + 1;
				}

				if(!body){
					all_data_from_the_response = calloc(l,sizeof(char));
					if(!all_data_from_the_response){
						close(sock_fd);
						return -1;
					}
				}else{
					*body = calloc(l,sizeof(char));
					if(!body){
						close(sock_fd);
						return -1;
					}
				}

				clean_CRNL(pbuf);
				/*clear the response properly*/
				clean_garbage(pbuf);
				if(&buff[0] == pbuf){
					size_t first_fragment = strlen(&buff[h_end]);
					strncpy( body ? *body : all_data_from_the_response,&buff[h_end],first_fragment);
					strncpy(body ? &(*body)[first_fragment] : &all_data_from_the_response[first_fragment],pbuf,strlen(pbuf));
					free(pbuf);
					clean_CRNL(body ? *body : all_data_from_the_response);
				}else{
					strncpy( body ? *body : all_data_from_the_response,pbuf,strlen(pbuf));
					free(pbuf);
					pbuf = NULL;
				}
				break;
			}


			int r = 0;
			if((r = handle_client_IO(ssl_client,0)) == 1){
				continue;
			}else if(r == 0 || r == 2){
				eof = 1;
				break;
			}
		}

		if(all_data_from_the_response){
			fwrite(all_data_from_the_response,1,strlen(all_data_from_the_response),stdout);
			free(all_data_from_the_response);
		}else if(body){
			if(*body == NULL){
				*body = calloc(strlen(pbuf)+1,sizeof(char));	
				if(!(*body)){
					close(sock_fd);
					return -1;
				}
				int inx = find_headers_end(pbuf,strlen(pbuf));
				if(inx == -1){
					strncpy(*body,pbuf,strlen(pbuf));
					if(pbuf != &buff[0])
						free(pbuf);
				}else{
					strncpy(*body,&pbuf[inx],strlen(&pbuf[inx]));
					if(pbuf != &buff[0])
						free(pbuf);
				}
			}
		}else{
			if(&buff[0] == pbuf){
				fwrite(buff,1,strlen(buff),stdout);
			}else{
				fwrite(pbuf,1,strlen(pbuf),stdout);
				free(pbuf);
			}
		}

		int ret = 0;
		while((ret = SSL_shutdown(ssl_client)) != 1){
			if(ret < 0 && handle_client_IO(ssl_client,ret) == 1)
				continue;

			close(sock_fd);
			return -1;
		}

	}else{
		if(write(sock_fd,req,strlen(req)) == -1){
			fprintf(stderr,"(%s): cannot send request to '%s'.\n",prog,URL);
			close(sock_fd);
			return -1;
		}
		if((bread = read(sock_fd,buff,MAX_BUF_SIZE)) == -1){
			fprintf(stderr,"(%s): cannot read from '%s'.\n",prog,URL);
			close(sock_fd);
			return -1;
		}
	}

	close(sock_fd);
	int index = find_headers_end(buff, (size_t)bread);

	if(body && !(*body)){
		*body = calloc(strlen(&buff[index])+1,sizeof(char));		
		if(!(*body)){

		}
		strncpy(*body,&buff[index],strlen(&buff[index]));
	}else{
		fprintf(stderr,"\n%s\n",&buff[index]);
	}
	return 0;
}

int parse_URL(char *URL, struct Url *url)
{
	if(!URL) return -1;

	char *d = strstr(URL,"//");
	if(!d) return -1;

	strncpy(url->protocol,URL,d - URL -1);
	d += 2;
	int start_host = d - URL;
	char *d_s = strstr(d,"/"); 
	if(!d_s){
		/*in the url we have only the host*/
		strncpy(url->host,&URL[start_host],strlen(&URL[start_host]));
		url->resource[0] = '/';
		return 0;
	}	
	
	int end_host = d_s - URL;
	strncpy(url->host,&URL[start_host],end_host - start_host);
	strncpy(url->resource,d_s,strlen(&URL[end_host]));
	return 0;
}

static int SSL_client_setup(SSL_CTX **ctx)
{

	*ctx = SSL_CTX_new(TLS_client_method());
	if(!(*ctx))
		return -1;

	SSL_CTX_set_verify(*ctx,SSL_VERIFY_PEER,NULL);

	if(!SSL_CTX_set_default_verify_paths(*ctx))
		return -1;

	if(!SSL_CTX_set_min_proto_version(*ctx,TLS1_2_VERSION))
		return -1;
	return 0;
}

static int handle_client_IO(SSL *ssl, int ret)
{
	int err = SSL_get_error(ssl,ret);
	ERR_print_errors_fp(stderr);
	switch(err){
		case SSL_ERROR_NONE:
			return 2;
		case SSL_ERROR_ZERO_RETURN:
		case SSL_ERROR_SYSCALL:
			return 0;
		case SSL_ERROR_WANT_READ:
			if(wait_for_activity(ssl,0) == -1)
				return -1;
			return 1;
		case SSL_ERROR_WANT_WRITE:
			if(wait_for_activity(ssl,1) == -1)
				return -1;
			return 1;
		case SSL_ERROR_SSL:
			return -1;
		case SSL_ERROR_WANT_CONNECT:
		case SSL_ERROR_WANT_ACCEPT:
			return 1;
		default:
			return -1;
	}
	return -1;
}

static int wait_for_activity(SSL *ssl, int w_r)
{
	int fd = SSL_get_fd(ssl);
	if(start_monitor(fd) == -1)
		return -1;

	modify_monitor_event(fd,w_r ? EPOLLOUT : EPOLLIN);
	int n;
    do { n = monitor_events(-1); } while(n == MONITOR_INTERRUPTED);
	return n;
}

static long read_hex_for_transfer_encoding(char *hex, long *h_end)
{
	char *t = strstr(hex,"\r\n");
	int t_pos = (int)(t - hex);
	*t = '\0';
	t--;
	while(*t != '\0' && *t != '\r' && *t != '\n'){ 
		t--; 
	}
	
	*h_end += strlen(++t) + 2;        
	long n = strtol(t,NULL,16);
	hex[t_pos] = '\r';
	return  n;
}

static void clean_CRNL(char *str)
{
	char *n = NULL;
	int c = 0;
	while((n = strstr(str,"\r\n"))){
		if(c == 2) return;
		*n = ' ';
		n++;
		*n = ' ';	
		c++;
	}
}
static void clean_garbage(char *str)
{
	char *space = NULL;
	while(( space = strstr(str, "  "))){
		int start = space - str;
		space += 2;
		while(*space != ' ') space++;
		

		int end = ++space - str;
		if((end - start) > 8)
			return;
		
		size_t s = strlen(&str[end+1]);
		char cpy[s+1];
		memset(cpy,0,s+1);
		strncpy(cpy,&str[end+1],s);
		strncpy(&str[start],cpy,s);
		str[start + s]= '\0';
		int trailing = strlen(&str[start+s+1]);
		if(trailing > 0)
			memset(&str[start + s],0,trailing);
	}
}

int req_builder(int method, char *urlstr, char *format_str, char *req, int length,int mode)
{ 
	struct Url url = {0};
	if(parse_URL(urlstr,&url) == -1)
		return -1;

	if(mode != USER_FIELDS){
	switch(method){
		case GET:
			if(snprintf(req,1024,format_str,"GET", 
						url.resource, 
						"HTTP/1.1",
						url.host,
						"wser") == -1){
				fprintf(stderr,"(%s): cannot form GET request.",prog);
				return -1;
			}
			break;
		case POST:
			if(snprintf(req,1024,format_str,"POST", 
						url.resource, "HTTP/1.1",
						url.host,
						"wser",
						length) == -1){

				fprintf(stderr,"(%s): cannot form GET request.",prog);
				return -1;
			}
			break;
		default:
	}

	} else{
		/*build custom request*/
		char cpy[1024] = {0};
		switch(method){
		case GET:
			if(snprintf(cpy,1024,CUSTOM_STR_REQUEST,"GET",
							url.resource,
							"HTTP/1.1") == -1){
				fprintf(stderr,"(%s): cannot form GET request.",prog);
				return -1;
			}
			int l = strlen(cpy);
			if(snprintf(&cpy[l],1024-l,"%s",req) == -1){
				fprintf(stderr,"(%s): cannot form GET request.",prog);
				return -1;
			}

			memset(req,0,1024);
			memcpy(req,cpy,strlen(cpy));
			break;
		default:
		}
	}
	return 0;
}


static void debugf(char *fmt)
{
	char *start = fmt;
	for(;*fmt;fmt++){
		if(*fmt =='\r'){
			printf("\\r");
			continue;
		}
		if(*fmt == '\n'){
			printf("\\n");
			continue;
		}

		printf("%c",*fmt);
	}
	fmt = start;
	printf("\n====================\n");
}
