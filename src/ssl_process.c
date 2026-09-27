#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include "load.h"
#include "handlesig.h"
#include "ssl_process.h"
#include "network.h"
#include "request.h"
#include "response.h"
#include "monitor.h"

struct p_info{
	pid_t p;
	time_t t;
	int exited;
};

struct p_info proc_list[100] = {0};
#define TIME_OUT 300 /*5 minutes*/
#define EIGHTkib_limit 8192


static char prog[] = "wser";

#ifdef OWN_DB

#include "worker_process.h" /* database handler*/

static int process_request(struct Request *req, int cli_sock, int work_proc_data_sock);
#else
static int process_request(struct Request *req, int cli_sock);
#endif

static int handle_ssl_steps(struct Connection_data *cd, 
							int cli_sock,
							struct Request *req,
							SSL **ssl,
							SSL_CTX **ctx);


int SSL_work_process(int data_sock)
{

#ifdef OWN_DB
	int work_proc_data_sock = -1;

	pid_t work_proc_pid = server_fork();

	if(work_proc_pid == -1){
		/*Parent*/
		fprintf(stderr,"(%s): architecture cannot be implemented.\n",prog);
		return -1;
	}

	if(work_proc_pid == 0){
		/*CHILD*/
		/* start DB handle process */	
		if((work_proc_data_sock = listen_UNIX_socket(-1,INT_PROC_SOCK_DB)) == -1) {
			fprintf(stderr,"cannot start Data base.\n");
			signal_server_parent(SIGINT);
		 	exit(-1);
		}

		
		db_sock = work_proc_data_sock;
		if(handle_sig_db_process() == -1)
			exit(1);

		work_process(work_proc_data_sock);
		return -1;
	}
	
	/*parent*/
	db_proc = work_proc_pid;

#endif /* OWN_DB -make flag*/

	if(start_monitor(data_sock) == -1){
		fprintf(stderr,"(%s): cannot start SSL context.\n",prog);
		signal_server_parent(SIGINT);
		exit(-1);
	}

	if(init_SSL(&ctx) == -1){
		fprintf(stderr,"(%s): cannot start SSL context.\n",prog);
		stop_monitor();
		signal_server_parent(SIGINT);
		exit(-1);
	}

	/*setting up to receiving file descriptor from another process*/
	int            data, cli_sock;
	struct iovec   iov;
	struct msghdr  msgh;

	/* Allocate a char buffer for the ancillary data. See the comments
	   in sendfd() */
	union {
		char   buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} controlMsg;
	struct cmsghdr *cmsgp;

	/* The 'msg_name' field can be used to obtain the address of the
	   sending socket. However, we do not need this information. */

	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;

	/* Specify buffer for receiving real data */

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	iov.iov_base = &data;       /* Real data is an 'int' */
	iov.iov_len = sizeof(int);

	/* Set 'msghdr' fields that describe ancillary data */

	msgh.msg_control = controlMsg.buf;
	msgh.msg_controllen = sizeof(controlMsg.buf);

	SSL *ssl_cli = NULL;
	for(;;){
		
		if((nfds = monitor_events(-1)) == -1) goto teardown_a;
		if(nfds == MONITOR_INTERRUPTED){
			if(reload_certificate){
				reload_certificate = 0;
				SSL_CTX_free(ctx);
				ctx = NULL;
				if(init_SSL(&ctx) == -1){
					fprintf(stderr,"(%s): cannot start SSL context.\n",prog);
					stop_monitor();
#ifdef OWN_DB		
					signal_server_process(db_proc,SIGINT);
#endif
					signal_server_parent(SIGINT);
					exit(-1);
				}
				continue;
			}
			continue;/*you might want to change this to got teardown*/
		}

		int i;
		for(i = 0; i < nfds; i++){
			/* Receive ancillary data; real data is ignored */
			int sock = -1;
			if(events[i].data.fd == data_sock){
				if((sock = accept(data_sock,NULL,NULL)) == -1)
					continue;

				errno = 0;
				if(recvmsg(sock, &msgh, 0) == -1){
					if(add_socket_to_monitor(sock, EPOLLIN) == -1) 
						continue;

					if(errno == EAGAIN || errno == EWOULDBLOCK)
						continue;

					stop_listening(sock);
					continue;
				}
			}else{
				if(recvmsg(sock, &msgh, 0) == -1){
					if(errno == EAGAIN || errno == EWOULDBLOCK)
						continue;

					stop_listening(sock);
					continue;
				}
			}

			cmsgp = CMSG_FIRSTHDR(&msgh);
			if (cmsgp == NULL
					|| cmsgp->cmsg_len != CMSG_LEN(sizeof(int))
					|| cmsgp->cmsg_level != SOL_SOCKET
					|| cmsgp->cmsg_type != SCM_RIGHTS) continue;


			memcpy(&cli_sock, CMSG_DATA(cmsgp), sizeof(int));

			int child_slot;
            for(child_slot = 0; child_slot < 100; ++child_slot){
                if(proc_list[child_slot].p <= 0 || !server_child_running(proc_list[child_slot].p)) break;
            }
            if(child_slot == 100){
                close(cli_sock);
                close(sock);
                continue; /* at capacity: do not crash the service or leak a child */
            }
            pid_t child = server_fork();
			if(child == 0){
				/*clear ssl que error*/
				ERR_clear_error(); 
				/*free resources that the child does not need*/
				stop_listening(sock);
				stop_listening(data_sock);
#if OWN_DB
				int db_sock = connect_UNIX_socket(-1,INT_PROC_SOCK_DB);
#endif

				if(start_monitor(cli_sock) == -1) {
					fprintf(stderr,"(%s): monitor event startup failed.\n",prog);
					goto teardown_a;
				}

				struct Request req = {0};
				int r = handle_ssl_steps(cds,cli_sock,&req,&ssl_cli,&ctx);

				if(r == -1) goto teardown_a;
                if(r == BAD_REQ){
                    struct Response res = {0};
                    if(generate_response(&res, 400, NULL, &req) == -1) goto teardown_a;
                    int w = write_cli_SSL(cli_sock, &res, cds);
                    clear_response(&res);
                    clear_request(&req);
                    if(w != SSL_WRITE_E) goto teardown_a;
                }
			
				if(r == 0 || r == 2){
#ifdef OWN_DB
					if(process_request(&req,cli_sock, db_sock) == 1)
#else 
					if(process_request(&req,cli_sock) == 1)
#endif
					{
						clear_request(&req);
						goto loop;
					}
					clear_request(&req);
					goto teardown_a;
				}

loop:
				int nfds =-1,j;
				for(;;){
					/*start monitoring event with a timer of 5 seconds*/
					if((nfds = monitor_events(5000)) == -1) goto teardown;
					if(nfds == MONITOR_INTERRUPTED){
						continue; /*change with goto teardwn in prod*/
					}
	
				
					for(j = 0; j < nfds; j++){
						int r = handle_ssl_steps(cds,events[j].data.fd,&req,&ssl_cli,&ctx);

						if(r == -1){
							/*shutdown*/
							goto teardown;
						}

						switch(r){
                        case SSL_READ_E:
                        case SSL_WRITE_E:
                        case HANDSHAKE:
                            break; /* resume only after the requested readiness event */
						case 2:
						case 0:
						{
							/*process request*/
#ifdef OWN_DB
							if(process_request(&req,events[j].data.fd,db_sock) == 1)
#else 
							if(process_request(&req,events[j].data.fd) == 1)
#endif
							{
								clear_request(&req);
								continue;
							}
							goto teardown;
						}
						case BAD_REQ:
						{
							struct Response res = {0};
							/*send a bad request response*/
							if(generate_response(&res,400,NULL,&req) == -1) {
								clear_response(&res);
								goto teardown;
							}

							int w = 0;
							if((w = write_cli_SSL(events[j].data.fd,&res,cds)) == -1) {
								clear_response(&res);
								goto teardown;
							}

							if(w == SSL_WRITE_E){
								clear_response(&res);
								break;
							}
							clear_response(&res);
							goto teardown;
						}
						case WRITE_OK:
                        case CLEAN_TEARDOWN:
							goto teardown;
						case SSL_CLOSE:
						case SSL_SET_E:
						case SSL_HD_F:
						default:
						remove_socket_from_monitor(cli_sock);
						stop_monitor();
						clear_request(&req);
						clean_connecion_data(cds,events[j].data.fd);
						SSL_CTX_free(ctx);
#if OWN_DB
						close(db_sock);
#endif
						exit(1);
						}
					}
				}
teardown_a:
			clean_connecion_data(cds,cli_sock);
			remove_socket_from_monitor(cli_sock);
			SSL_CTX_free(ctx);
			ctx = NULL;
			stop_monitor();
			exit(0);
teardown:
			remove_socket_from_monitor(cli_sock);
			clean_connecion_data(cds,events[j].data.fd);
			SSL_CTX_free(ctx);
			ctx = NULL;
			stop_monitor();
#if OWN_DB
			close(db_sock);
#endif
			exit(0);
		}else if(child == -1){
			/*PARENT*/
			stop_listening(cli_sock);
			stop_listening(sock);
			/*wait on the children*/
			continue;
		}else{
			/*PARENT*/
			stop_listening(cli_sock);
			stop_listening(sock);

            proc_list[child_slot].p = child;
            proc_list[child_slot].t = time(NULL);
            int i;
            /*wait on the children*/
			for(i = 0; i < 100;i++){
				if(proc_list[i].p == 0 || proc_list[i].p == -1)
					continue;

				errno = 0;
				if(!server_child_running(proc_list[i].p)){
					proc_list[i].p = -1;
					proc_list[i].t = 0;
					continue;
				}

				if(proc_list[i].t > 0 && ((time(NULL) - proc_list[i].t ) > (time_t) TIME_OUT)){
					if(signal_server_process(proc_list[i].p,SIGKILL) == 0){
						continue;
					}
				}
			}
		}
		}
	}
	SSL_CTX_free(ctx);
	ctx = NULL;
	clean_connecion_data(cds,-1);
	return 0;
}

static int handle_ssl_steps(struct Connection_data *cd, int cli_sock,
        struct Request *req, SSL **ssl, SSL_CTX **ctx)
{
    int i;
    for(i = 0; i < MAX_CON_DAT_ARR; ++i) if(cd[i].fd == cli_sock) break;
    if(i == MAX_CON_DAT_ARR){
        if(cli_sock < 0) return -1;
        for(i = 0; i < MAX_CON_DAT_ARR; ++i) if(cd[i].fd <= 0) break;
        if(i == MAX_CON_DAT_ARR) return -1;
        SSL *session = SSL_new(*ctx);
        if(!session) return -1;
        if(!SSL_set_fd(session, cli_sock)){ SSL_free(session); return -1; }
        cd[i].fd = cli_sock;
        cd[i].ssl = session;
        *ssl = session;
    }
    if(cd[i].retry_write){
        int r = write_cli_SSL(cli_sock, NULL, cd);
        return r == 0 ? WRITE_OK : r;
    }
    if(cd[i].close_notify){
        int r = SSL_shutdown(cd[i].ssl);
        if(r == 1) return CLEAN_TEARDOWN;
        if(r < 0){
            int err = SSL_get_error(cd[i].ssl, r);
            if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) return -1;
            if(modify_monitor_event(cli_sock, err == SSL_ERROR_WANT_WRITE ? EPOLLOUT : EPOLLIN) == -1) return -1;
        }
        return SSL_CLOSE;
    }
    return read_cli_sock_SSL(cli_sock, req, cd);
}

#if OWN_DB
static int process_request(struct Request *req, int cli_sock, int work_proc_data_sock)
#else
static int process_request(struct Request *req, int cli_sock)
#endif
{
	switch(req->method){
	case GET:
    case HEAD:
	{
		struct Response res = {0};
		struct Content cont = {0};
		/* Load content */	
		/*check if the req->resource is an end point for the db or a website page*/
#if OWN_DB
		if(!strstr(req->resource,".html")
			&& !strstr(req->resource,".css")
			&& !strstr(req->resource,".js")
			&& !((strlen(req->resource) == 1) && strncmp(req->resource,"/",1) == 0)){

			fprintf(stderr,"resource is %s\n",req->resource);
		if(load_resource_db(req,&cont,work_proc_data_sock) == 400){
				/*send not found response*/
				if(cont.cnt_st[0] != '\0'){
					if(generate_response(&res,404,&cont,req) == -1) break;
				}else{
					if(generate_response(&res,404,NULL,req) == -1) break;
				}

				int w = 0;
				if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
				if(w == SSL_WRITE_E){
					clear_response(&res);
					clear_content(&cont);
					return 1;
				}
				clear_response(&res);
				clear_content(&cont);
				return 0;
		}
		/*send 200 response*/
		if(generate_response(&res,200,&cont,req) == -1) {
			clear_content(&cont);
			clear_response(&res);
			return 0;
		}

		clear_content(&cont);
		int w = 0;
		if((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
			clear_response(&res);
			return 0;
		}

		if(w == SSL_WRITE_E){
			clear_response(&res);
			return 1;
		}
		clear_response(&res);
		return 0;

		} else{

#endif
			if(load_resource(req->resource,&cont) == -1){
				/*send not found response*/
				if(generate_response(&res,404,NULL,req) == -1) break;

				int w = 0;
				if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) break;
				if(w == SSL_WRITE_E){
					clear_response(&res);
					clear_content(&cont);
					return 1;
				}
				clear_response(&res);
				clear_content(&cont);
				return 0;
			}

			/*send 200 response*/
			if(generate_response(&res,OK,&cont,req) == -1) {
				clear_content(&cont);
				clear_response(&res);
				return 0;
			}

			clear_content(&cont);
			int w = 0;
			if((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
				clear_response(&res);
				return 0;
			}

			if(w == SSL_WRITE_E){
				clear_response(&res);
				return 1;
			}
			clear_response(&res);
			return 0;
#if OWN_DB
		}
		return 0;
#endif
	}
	case OPTIONS:
	{
		struct Response res = {0};
		size_t s = strlen(req->origin);
		if(s != strlen(ORIGIN_DEF) 
				|| strncmp(req->origin,ORIGIN_DEF,strlen(ORIGIN_DEF)) != 0) {
			/*send bad request*/
			/*send a bed request response*/
			if(generate_response(&res,400,NULL,req) == -1) {
				clear_response(&res);
				return -1;
			}

			int w = 0;
			if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) {
				clear_response(&res);
				return -1;
			}

			if(w == SSL_WRITE_E){
				clear_response(&res);
				return 1;
			}
			clear_response(&res);
			return 0;
		}

		/*send a response to the options request*/
		if(generate_response(&res,200,NULL,req) == -1) break;

		clear_request(req);
		int w = 0;

		if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) {
			clear_response(&res);
			return -1;
		}

		if(w == SSL_WRITE_E){
			clear_response(&res);
			return 1;
		}

		clear_response(&res);
		return 0;
	}
	case BAD_REQ:
	{
		struct Response res = {0};
		/*send a bed request response*/
		if(generate_response(&res,400,NULL,req) == -1) {
			clear_response(&res);
			return -1;
		}

		int w = 0;
		if((w = write_cli_SSL(cli_sock,&res,cds)) == -1) {
			clear_response(&res);
			return -1;
		}

		if(w == SSL_WRITE_E){
			clear_response(&res);
			return 1;
		}
		clear_response(&res);
		return 0;
	}
	case POST:
#if OWN_DB
	{
		struct Response res = {0};
		struct Content cont = {0};

		fprintf(stderr,"POST branch resource is %s\n",req->resource);		
		int load_code = load_resource_db(req,&cont,work_proc_data_sock);
		
		if(generate_response(&res,load_code,&cont,req) == -1) {
			clear_content(&cont);
			clear_response(&res);
			return 0;
		}

		clear_content(&cont);
		int w = 0;
		if((w = write_cli_SSL(cli_sock,&res,cds)) == -1){
			clear_response(&res);
			return 0;
		}

		if(w == SSL_WRITE_E){
			clear_response(&res);
			return 1;
		}
		clear_response(&res);
		return 0;
	}
#endif
	case PUT:
	case DELETE:
	default:
	return 0;
	}
	return -1;
}

