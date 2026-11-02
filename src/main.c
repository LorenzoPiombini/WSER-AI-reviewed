#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h> 
#include <unistd.h> 
#include <openssl/ssl.h> 
#include <sys/socket.h>
#include "network.h" 
#include "load.h"
#include "request.h"
#include "monitor.h"
#include "default.h"
#include "handlesig.h"
#include "response.h"
#include "ssl_process.h"
#include "http_process.h"

#if OWN_DB

#include "work_process.h" /* database handler*/
#include "end_points.h"
#include "lua_start.h"
#include "ctype.h"

#endif

char prog[] = "wser";

int main(int argc, char **argv)
{	
	int secure = 0;
	if(argc > 2) goto client;

    if(handle_sig_main_process() == -1) return -1;

	if(argc > 1 && *argv[1] == 's') secure = 1;

	if(check_default_setting() == -1){
		fprintf(stderr,"(%s): cannot start the server, configuration issue.",prog);
		return -1;
	} 

	/*start listening on port 80*/
	int con = -1, con80 = -1;
	uint16_t port = secure ? 443 : 80;
	if((con = listen_port_80(&port)) == -1){
		fprintf(stderr,"(%s): cannot listen to port %d.\n",prog,port);
		return -1;
	}


	fprintf(stdout,"(%s): listening on port %d...\n",prog,port);

	if(secure){
		/*listen also on port 80 to automate certificate renual and reloading */
		port = 80;
		if((con80 = listen_port_80(&port)) == -1){
			fprintf(stderr,"(%s): cannot listen to port %d.\n",prog,port);
			close(con);
			return -1;
		}
	}


	pid_t ssl_handle_child = -1;
	if(secure){
		ssl_handle_child = server_fork();
		if(ssl_handle_child == -1){
			stop_listening(con);
			return -1;
		}

		/*start SSL handle process*/
		if(ssl_handle_child == 0){
            close(con);
            if(con80 >= 0) close(con80);
			int data_sock = -1;
			if((data_sock = listen_UNIX_socket(SOCK_NONBLOCK,INT_PROC_SOCK_SSL)) == -1){
				if(ssl_handle_child > 0) signal_server_process(ssl_handle_child,SIGINT);
				exit(1);
				return -1;
			}

			/*start signal handle for this process*/
			ssl_sock = data_sock;
			if(handle_sig_ssl_process() == -1)
				exit(1);

			SSL_work_process(data_sock);
			exit(1);
		}

	}

	ssl_proc = ssl_handle_child;
	/* 
	 * setup needed
	 * to send client socket file descriptors to the SSL and HTTP process
	 * */

	int data; 
	struct iovec iov;
	struct msghdr msgh = {0};
	struct cmsghdr *cmsgp;

	/* Ancillary data buffer, wrapped in a union
	   in order to ensure it is suitably aligned */
	union {        
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;

	msgh.msg_name = NULL;
	msgh.msg_namelen = 0;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	iov.iov_base = &data;
	iov.iov_len = sizeof(int);
	data = 1234;

	/* Set 'msghdr' fields that describe ancillary data */
	msgh.msg_control = u.buf;
	msgh.msg_controllen = sizeof(u.buf);

	/* Set up ancillary data describing file descriptor to send */
	cmsgp = CMSG_FIRSTHDR(&msgh);
	cmsgp->cmsg_level = SOL_SOCKET;
	cmsgp->cmsg_type = SCM_RIGHTS;
	cmsgp->cmsg_len = CMSG_LEN(sizeof(int));


	pid_t port_80_handle_child = server_fork();
	if(port_80_handle_child == -1){
		if(ssl_handle_child > 0) signal_server_process(ssl_handle_child,SIGINT);
		stop_listening(con);
		return -1;
	}


	/*start 80(HTTP) and cert renewal handle process*/
	if(port_80_handle_child == 0){
        close(con);
        if(con80 >= 0) close(con80);
		int data_sock = -1;
		if((data_sock = listen_UNIX_socket(SOCK_NONBLOCK,INT_PROC_SOCK_PORT_EIGTHY_CERT_REN)) == -1){
			if(ssl_handle_child > 0) signal_server_process(ssl_handle_child,SIGINT);
			exit(1);
			return -1;
		}

		/*start signal handle for HTTP process*/
		http_sock = data_sock;
		if(handle_sig_http_process() == -1)
			exit(1);

		HTTP_work_process(data_sock,secure);
		if(ssl_handle_child > 0) signal_server_process(ssl_handle_child,SIGINT);
		signal_server_parent(SIGINT);
		exit(1);
	}

	
	http_proc = port_80_handle_child;
	hdl_sock = con;

	if(start_monitor(con) == -1) {
		fprintf(stderr,"(%s): monitor event startup failed.\n",prog);
		stop_listening(con);
		return -1;
	}
	
	if(con80 != -1){
		if(add_socket_to_monitor(con80, EPOLLIN) == -1) 
			return -1;
	}

	int cli_sock = -1;
	struct Response res;
	memset(&res,0,sizeof(struct Response));

	for(;;){
		if((nfds = monitor_events(-1)) == -1) break;	
		if(nfds == MONITOR_INTERRUPTED) continue;
		for(int i = 0; i < nfds; i++){

			struct Request req;
			memset(&req,0,sizeof(struct Request));
			req.method = -1;
			int r = 0;
			if(secure){
				if(events[i].data.fd == con){
					if((r = wait_for_connections_SSL(con,&cli_sock)) == -1) break;

					if(r == EAGAIN || r == EWOULDBLOCK) continue;

					memcpy(CMSG_DATA(cmsgp), &cli_sock, sizeof(int));

					errno = 0;
					int data_sock = connect_UNIX_socket(-1,INT_PROC_SOCK_SSL);
					if(data_sock == -1){
						stop_listening(cli_sock);
						continue;
					}

					/*send ancillary data to data sock*/
					if(sendmsg(data_sock, &msgh,0) == -1){
						stop_listening(cli_sock);
						int fd_holder = -1;
						memcpy(CMSG_DATA(cmsgp), &fd_holder, sizeof(int));
						continue;
					}
					msgh.msg_controllen = sizeof(u.buf); // Reset this every time!
					stop_listening(data_sock);
					stop_listening(cli_sock);
					continue;
				}else if(events[i].data.fd == con80){ /*handle renew certificate*/
					if((r = wait_for_connections(con80,&cli_sock,&req,MULTI_PROC)) == -1) break;
					if(r == EAGAIN || r == EWOULDBLOCK) continue;
			
					memcpy(CMSG_DATA(cmsgp), &cli_sock, sizeof(int));

					errno = 0;
					int data_sock = connect_UNIX_socket(-1,INT_PROC_SOCK_PORT_EIGTHY_CERT_REN);
					if(data_sock == -1){
						stop_listening(cli_sock);
						continue;
					}

					/*send ancillary data to data sock*/
					if(sendmsg(data_sock, &msgh,0) == -1){
						stop_listening(cli_sock);
						stop_listening(data_sock);
						int fd_holder = -1;
						memcpy(CMSG_DATA(cmsgp), &fd_holder, sizeof(int));
						continue;
					}
					msgh.msg_controllen = sizeof(u.buf); // Reset this every time!
					stop_listening(data_sock);
					stop_listening(cli_sock);
					continue;
				}
			}
			if((r = wait_for_connections(con,&cli_sock,&req,MULTI_PROC)) == -1) break;
			if(r == EAGAIN || r == EWOULDBLOCK) continue;

			memcpy(CMSG_DATA(cmsgp), &cli_sock, sizeof(int));

			errno = 0;
			int data_sock = connect_UNIX_socket(-1,INT_PROC_SOCK_PORT_EIGTHY_CERT_REN);
			if(data_sock == -1){
				stop_listening(cli_sock);
				continue;
			}

			/*send ancillary data to data sock*/
			if(sendmsg(data_sock, &msgh,0) == -1){
				stop_listening(cli_sock);
				int fd_holder = -1;
				memcpy(CMSG_DATA(cmsgp), &fd_holder, sizeof(int));
				continue;
			}
			stop_listening(cli_sock);
			close(data_sock);
			continue;

		}
	}

	stop_monitor();
	stop_listening(con);
	if(secure)
		stop_listening(con80);
	return 0;
	/*real end of main if used as a server*/

client:

	int option = 0;
	int i;
	while((option = getopt(argc,argv,"g:")) != -1){
		switch(option){
			case 'g':
				{
					char buff[1024] = {0};
					int wrote = 0;
					int personalized_req = 0;
					if(argc > 3){
						personalized_req = USER_FIELDS;	
						for(i = 0; i < argc;i++){
							if(strncmp(argv[i],"-h",2) == 0){
								/*Grab the header field and build a new request*/
								if(argv[i+1]){
									int l = strlen(argv[i+1]);
									if(snprintf(&buff[wrote],l+3,"%s\r\n",argv[i+1]) == -1)
										return -1;
									wrote += l+2;
								}
							}
						}

						if(snprintf(&buff[wrote],3,"%s","\r\n") == -1)
							return -1;
					}
					/*create get request*/
					if(req_builder(GET, optarg,F_STR_GET, buff,0,personalized_req) == -1)
						return -1;
					perform_http_request(optarg,buff,NULL);
					SSL_client_close();
					break;
				}
			default:
				break;
		}
	}

	return 0;
}
