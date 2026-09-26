#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include "load.h"
#include "handlesig.h"
#include "network.h"
#include "request.h"
#include "response.h"
#include "monitor.h"
#include "http_process.h"

struct p_info{
	pid_t p;
	time_t t;
	int exited;
};

struct p_info proc_list_HTTP[100] = {0};
#define TIME_OUT 300 /*5 minutes*/
#define EIGHTkib_limit 8192


static char prog[] = "wser";


#ifdef OWN_DB
	#include "work_process.h" /* database handler*/
#endif
static int process_request(struct Request *req, int cli_sock,int result_of_http_step,int secure, int db_sock);

static int http_step(int sock,struct Request *req);

int HTTP_work_process(int data_sock,int secure)
{

#ifdef OWN_DB
		/*this is needed for testing
		 * when we run the server on port 80, but we need to test the entire architecture 
		 * becuase we do not have a safe connection
		 * */
	if(!secure){
		int work_proc_data_sock = -1;

		pid_t work_proc_pid = fork();

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
				kill(getppid(),SIGINT);
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
	}

#endif /* OWN_DB -make flag*/

	if(start_monitor(data_sock) == -1){
		fprintf(stderr,"(%s): cannot start HTTP process correctly\n",prog);
		kill(getppid(),SIGINT);
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

	for(;;){

		if((nfds = monitor_events(-1)) == -1) goto teardown;
		if(nfds == EINTR) continue;

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

			pid_t child = fork();
			if(child == 0){
				/*child do not need these */
				stop_listening(sock);
				stop_listening(data_sock);

				/*handle the request*/
#if OWN_DB
				int db_sock = -1;
				if(!secure){
					connect_UNIX_socket(-1,INT_PROC_SOCK_DB);
				}
#endif
				if(start_monitor(cli_sock) == -1) {
					fprintf(stderr,"(%s): monitor event startup failed.\n",prog);
					goto teardown;
				}

				struct Request req = {0};
				int r = http_step(cli_sock,&req);
				if(r == -1) goto teardown;

				if(r == EAGAIN || r == EWOULDBLOCK) goto loop;
#ifdef OWN_DB
				if(!secure){
					process_request(&req,cli_sock,r,secure, db_sock);
				} else{
					process_request(&req,cli_sock,r,secure,-1);
				}
#else
				process_request(&req,cli_sock,r,secure,-1);
				clear_request(&req);
#endif
				goto teardown;/**/
loop:
				int nfd =-1,j;
				for(;;){
					if((nfd = monitor_events(-1)) == -1) goto teardown;
					if(nfd == EINTR){
						continue; /*change with goto teardwn in prod*/
					}

					for(j = 0; j < nfd; j++){
						int r = http_step(events[j].data.fd,&req);
                        if(r == -1) goto teardown;
						if(r == EAGAIN || r == EWOULDBLOCK) break;
#ifdef OWN_DB
						if(!secure){
							process_request(&req,events[j].data.fd,r,secure, db_sock);
						}else{
							process_request(&req,events[j].data.fd,r,secure,-1);
						}
#else
						process_request(&req,events[j].data.fd,r,secure,-1);
						clear_request(&req);
#endif
						goto teardown;
					}
				}
teardown:
				stop_listening(cli_sock);
				stop_monitor();
#ifdef OWN_DB
				if(!secure){
					close(db_sock);
				}
#endif
				exit(0);
			}else if(child == -1){ /*PARENT*/

				stop_listening(cli_sock);
				stop_listening(sock);
				continue;
			}else{
				/*PARENT*/
				stop_listening(cli_sock);
				stop_listening(sock);

				int i;
				for(i = 0; i < 100;i++){
					if(proc_list_HTTP[i].p == 0 || proc_list_HTTP[i].p == -1){
						proc_list_HTTP[i].p = child;
						proc_list_HTTP[i].t = time(NULL);
						break;
					}
				}

				assert(i < 100);
				/*wait on the children*/
				for(i = 0; i < 100;i++){
					if(proc_list_HTTP[i].p == 0 || proc_list_HTTP[i].p == -1)
						continue;

					errno = 0;
					if(kill(proc_list_HTTP[i].p,0) == -1 && errno == ESRCH){
						proc_list_HTTP[i].p = -1;
						proc_list_HTTP[i].t = 0;
						continue;
					}

					if(proc_list_HTTP[i].t > 0 && ((time(NULL) - proc_list_HTTP[i].t ) > (time_t) TIME_OUT)){
						if(kill(proc_list_HTTP[i].p,SIGKILL) == 0){
							proc_list_HTTP[i].p = -1;
							proc_list_HTTP[i].t = 0;
							continue;
						}
					}
				}
			}
		}/*end inner loop*/

	}

	stop_listening(cli_sock);
#ifdef OWN_DB
	if(!secure){
		close(db_sock);
	}
#endif
	return -1;
}

static int http_step(int sock,struct Request *req)
{
	int e = 0;
	if(( e = read_cli_sock(sock,req)) == -1){
		fprintf(stderr,"(%s): cannot read data from socket",prog);
		return -1;
	}

	if( e == EAGAIN || e == EWOULDBLOCK || e == BAD_REQ) return e;
	return 0;
}

static int process_request(struct Request *req, int cli_sock,int result_of_http_step,int secure, int db_sock)
{

	struct Content cont = {0};
	struct Response res = {0};

	if(result_of_http_step == BAD_REQ) goto bad_request;
	switch(req->method){
		case GET:
        case HEAD:
			if(secure){
				if(strstr(req->resource,AUTO_CERT_RENEWAL)){
					/*load the file, and send it*/
					if(load_resource(req->resource,&cont) == -1){
						/*send not found response*/
						if(generate_response(&res,404,&cont,req) == -1) break;

						int w = 0;
						if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
						if(w == EAGAIN || w == EWOULDBLOCK){
							uint8_t ws = 0;
							while((w = write_cli_sock(cli_sock,&res)) != -1){
								if(w == EAGAIN || w == EWOULDBLOCK) continue;

								ws = 1;
								break;
							}


							if(ws){
								clear_response(&res);
								clear_content(&cont);
								return 0;
							}

							clear_response(&res);
							clear_content(&cont);
							return -1;
						}

						clear_response(&res);
						clear_content(&cont);
						return -1;
					}

					/*send 200 response*/
					if(generate_response(&res,OK,&cont,req) == -1) {
						/*TODO: server errror*/
						clear_response(&res);
						clear_content(&cont);
						return -1;
					}

					clear_content(&cont);
					int w = 0;
					if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
					if(w == EAGAIN || w == EWOULDBLOCK){
						uint8_t ws = 0;
						while((w = write_cli_sock(cli_sock,&res)) != -1){
							if(w == EAGAIN || w == EWOULDBLOCK) continue;

							ws = 1;
							break;
						}	
						if(ws){
							kill(ssl_proc,SIGHUP);
							clear_response(&res);
							return 0;
						}
						clear_response(&res);
						return -1;
					}

					kill(ssl_proc,SIGHUP);
					clear_response(&res);
					return 0;
				}else{
					/*send 301 response*/
					if(generate_response(&res,301,NULL,req) == -1) break;

					int w = 0;
					if((w = write_cli_sock(cli_sock,&res)) == -1) break;
					if(w == EAGAIN || w == EWOULDBLOCK){
						uint8_t ws = 0;
						while((w = write_cli_sock(cli_sock,&res)) != -1){
							if(w == EAGAIN || w == EWOULDBLOCK) continue;

							ws = 1;
							break;
						}


						if(ws){
							clear_response(&res);
							clear_content(&cont);
							return 0;
						}

						clear_response(&res);
						clear_content(&cont);
						return -1;
					}

					clear_response(&res);
					clear_content(&cont);
					return 0;
				}
				break;
			}
			/* Load content */	
			if(
#ifdef OWN_DB
                    (strstr(req->resource,".js")
						|| strstr(req->resource,".html")
						|| strstr(req->resource,".css")
						|| (strlen(req->resource) == 1 && (strncmp(req->resource,"/",1) == 0)))
#else
                    1
#endif
            ){
				if(load_resource(req->resource,&cont) == -1){
					/*send not found response*/
					if(generate_response(&res,404,&cont,req) == -1) break;

					int w = 0;
					if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
					if(w == EAGAIN || w == EWOULDBLOCK){
						uint8_t ws = 0;
						while((w = write_cli_sock(cli_sock,&res)) != -1){
							if(w == EAGAIN || w == EWOULDBLOCK) continue;
							ws = 1;
							break;
						}


						if(ws){
							clear_content(&cont);
							clear_response(&res);
							return 0;
						}

						clear_content(&cont);
						clear_response(&res);
						return -1;
					}

					clear_content(&cont);
					clear_response(&res);
					return -1;
				}
			}else{
#ifdef OWN_DB
				/*get data from the DB*/
				if(!secure){
					if(load_resource_db(req,&cont,db_sock) == -1) goto bad_request;
				}
#endif
			}

			/*send 200 response*/
			if(generate_response(&res,OK,&cont,req) == -1) {
				/*TODO: server errror*/
				clear_content(&cont);
				clear_response(&res);
				return -1;
			}

			clear_content(&cont);
			int w = 0;
			if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
			if(w == EAGAIN || w == EWOULDBLOCK){
				uint8_t ws = 0;
				while((w = write_cli_sock(cli_sock,&res)) != -1){
					if(w == EAGAIN || w == EWOULDBLOCK) continue;

					ws = 1;
					break;
				}
				if(ws){
					clear_response(&res);
					return 0;
				}
				clear_response(&res);
				return -1;
			}

			clear_response(&res);
			return 0;
		case OPTIONS:
			{
				if(secure){
					if(strstr(req->resource,AUTO_CERT_RENEWAL)){
						/*load the file, and send it*/
						if(load_resource(req->resource,&cont) == -1){
							/*send not found response*/
							if(generate_response(&res,404,&cont,req) == -1) break;

							int w = 0;
							if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
							if(w == EAGAIN || w == EWOULDBLOCK){
								uint8_t ws = 0;
								while((w = write_cli_sock(cli_sock,&res)) != -1){
									if(w == EAGAIN || w == EWOULDBLOCK) continue;

									ws = 1;
									break;
								}


								if(ws){
									clear_response(&res);
									clear_content(&cont);
									return 0;
								}

								clear_response(&res);
								clear_content(&cont);
								return -1;
							}

							clear_response(&res);
							clear_content(&cont);
							return -1;
						}

						/*send 200 response*/
						if(generate_response(&res,OK,&cont,req) == -1) {
							/*TODO: server errror*/
							clear_response(&res);
							clear_content(&cont);
							return -1;
						}

						clear_content(&cont);
						int w = 0;
						if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
						if(w == EAGAIN || w == EWOULDBLOCK){
							uint8_t ws = 0;
							while((w = write_cli_sock(cli_sock,&res)) != -1){
								if(w == EAGAIN || w == EWOULDBLOCK) continue;

								ws = 1;
								break;
							}	
							if(ws){
								kill(ssl_proc,SIGHUP);
								clear_response(&res);
								return 0;
							}
							clear_response(&res);
							return -1;
						}

						kill(ssl_proc,SIGHUP);
						clear_response(&res);
						return 0;
					}else{
						/*send 301 response*/
						if(generate_response(&res,301,NULL,req) == -1) break;

						int w = 0;
						if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
						if(w == EAGAIN || w == EWOULDBLOCK){
							uint8_t ws = 0;
							while((w = write_cli_sock(cli_sock,&res)) != -1){
								if(w == EAGAIN || w == EWOULDBLOCK) continue;

								ws = 1;
								break;
							}


							if(ws){
								clear_response(&res);
								clear_content(&cont);
								return 0;
							}

							clear_response(&res);
							clear_content(&cont);
							return -1;
						}

						clear_response(&res);
						clear_content(&cont);
						return 0;
					}
					break;
				}
				size_t s = strlen(req->origin);
				if(s != strlen(ORIGIN_DEF)) goto bad_request;

				if(strncmp(req->origin,ORIGIN_DEF,strlen(ORIGIN_DEF)) != 0) goto bad_request;


				/*send a response to the options request*/
				if(generate_response(&res,200,NULL,req) == -1) break;

				int w = 0;
				if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
				if(w == EAGAIN || w == EWOULDBLOCK){
					uint8_t ws = 0;
					while((w = write_cli_sock(cli_sock,&res)) != -1){
						if(w == EAGAIN || w == EWOULDBLOCK) continue;

						ws = 1;
						break;
					}

					if(ws) {
						clear_response(&res);
						return 0;
					}

					return -1;
				}

				clear_response(&res);
				return 0;
			}
			/*not implemented method **ON PORPUSE** */
		case DELETE:
		case POST:
		case PUT:
		default:
			{

				if(secure){
					if(strstr(req->resource,AUTO_CERT_RENEWAL)){
						/*load the file, and send it*/
						if(load_resource(req->resource,&cont) == -1){
							/*send not found response*/
							if(generate_response(&res,404,&cont,req) == -1) break;

							int w = 0;
							if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
							if(w == EAGAIN || w == EWOULDBLOCK){
								uint8_t ws = 0;
								while((w = write_cli_sock(cli_sock,&res)) != -1){
									if(w == EAGAIN || w == EWOULDBLOCK) continue;

									ws = 1;
									break;
								}


								if(ws){
									clear_response(&res);
									clear_content(&cont);
									return 0;
								}

								clear_response(&res);
								clear_content(&cont);
								return -1;
							}

							clear_response(&res);
							clear_content(&cont);
							return -1;
						}

						/*send 200 response*/
						if(generate_response(&res,OK,&cont,req) == -1) {
							/*TODO: server errror*/
							clear_response(&res);
							clear_content(&cont);
							return -1;
						}

						clear_content(&cont);
						int w = 0;
						if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
						if(w == EAGAIN || w == EWOULDBLOCK){
							uint8_t ws = 0;
							while((w = write_cli_sock(cli_sock,&res)) != -1){
								if(w == EAGAIN || w == EWOULDBLOCK) continue;

								ws = 1;
								break;
							}	
							if(ws){
								kill(ssl_proc,SIGHUP);
								clear_response(&res);
								return 0;
							}
							clear_response(&res);
							return -1;
						}

						kill(ssl_proc,SIGHUP);
						clear_response(&res);
						return 0;
					}else{
						/*send 301 response*/
						if(generate_response(&res,301,NULL,req) == -1) break;

						int w = 0;
						if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
						if(w == EAGAIN || w == EWOULDBLOCK){
							uint8_t ws = 0;
							while((w = write_cli_sock(cli_sock,&res)) != -1){
								if(w == EAGAIN || w == EWOULDBLOCK) continue;

								ws = 1;
								break;
							}


							if(ws){
								clear_response(&res);
								clear_content(&cont);
								return 0;
							}

							clear_response(&res);
							clear_content(&cont);
							return -1;
						}

						clear_response(&res);
						clear_content(&cont);
						return 0;
					}
					break;
				}
				if(generate_response(&res,400,NULL,req) == -1) break;

				int w = 0;
				if(( w = write_cli_sock(cli_sock,&res)) == -1) break;
				if(w == EAGAIN || w == EWOULDBLOCK){
					uint8_t ws = 0;
					while((w = write_cli_sock(cli_sock,&res)) != -1){
						if(w == EAGAIN || w == EWOULDBLOCK) continue;

						ws = 1;
						break;
					}

					if(ws) return 0;

					return -1;
				}

				clear_response(&res);

				return -1;
			}/*end default case*/
	}/*end switch statement*/

bad_request:
	/*send a bed request response*/
	if(generate_response(&res,400,NULL,req) == -1) return -1;

	int w = 0;
	if(( w = write_cli_sock(cli_sock,&res)) == -1) return -1;
	if(w == EAGAIN || w == EWOULDBLOCK){
		uint8_t ws = 0;
		while((w = write_cli_sock(cli_sock,&res)) != -1){
			if(w == EAGAIN || w == EWOULDBLOCK) continue;

			ws = 1;
			break;
		}

		if(ws) return 0;

		return -1;
	}
	clear_response(&res);
	return 0;
}
