#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h> 
#include <unistd.h> 
#include <fcntl.h>
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

char certificates_path[PATH_MAX] = {0};
char server_log_file[PATH_MAX] = {0};
#include <stdint.h>

#define ADDR_MASK 0x0000FFFFFFFFFFFFUL
char **domains = NULL;
enum instructions_per_arg{
	CLIENT = 0,
	SECURE = 1,
	PROD = 2,
	DOMAIN = 3
};


static int check_arg_list(int argc, char **argv,char ***domains,int *inst);
static int init_domains(char ** argv,uint64_t domains);
static void free_domains(char **domains,int domain_count);

#define GET_DOMS_COUNT(s) (((uint64_t)s) >> 48) 
char prog[] = "wser";

int main(int argc, char **argv)
{	
	/*this function pupulate TLS certificate path variable, and server log file variable*/
	if(check_default_setting() == -1){
		fprintf(stderr,"(%s): cannot start the server, configuration issue.",prog);
		return -1;
	} 

	int inst[4] = {-1,-1,-1,-1};
	int secure = 0;
	if (check_arg_list(argc,argv,&domains,inst) == -1) {
		printf("wrong arguments order or syntax\n");
		return -1;
	}
	
	char **d = (char **)((uint64_t)domains & ADDR_MASK);
	for(int i = 0; i < 4; i++){
		switch(inst[i]){
		default: break;
		case CLIENT: goto client;
		case SECURE: secure = 1; break;
		case DOMAIN: 
			if(domains == NULL){
				fprintf(stderr,"cannot start the server, domain needed.\n");
				return -1;
			}
			break;
		case PROD: 
			if(domains == NULL){
				fprintf(stderr,"cannot start the server, domain needed.\n");
				return -1;
			}
			
			pid_t child = fork();
			if(child == 0){
				/*in the child*/
				int in = open("/dev/null",O_RDONLY);
				int out = open(server_log_file,O_WRONLY |O_CREAT|O_TRUNC, 0664);
				if(in < 0 || out < 0){
					exit(1);
				}
				dup2(in,0);
				dup2(out,1);
				dup2(out,2);
				close(in);
				close(out);

				char *nohup_args[] = {"nohup","./wser",NULL};
				if(execv("/bin/nohup",nohup_args) == -1){
					printf("could not run the server in the background.\n");
					exit(1);
				}
				exit(0);
			}
			int nr_domains = (int)GET_DOMS_COUNT(domains);
			
			printf("running server in the background with %s serving ",secure ? "HTTPS":"HTTP");
			for(int i=0; i < nr_domains;i++){
				if(nr_domains - i > 1)
					printf("%s,",d[i]);
				else
					printf("%s\n",d[i]);
			}
			free_domains(d,nr_domains);
			return 0;
		}
	}

    if(handle_sig_main_process() == -1) return -1;


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

			SSL_work_process(data_sock,(uint64_t)domains);
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
static int check_arg_list(int argc, char **argv,char ***domains,int *inst)
{

	if(argc == 1) return 0; /*should start tnhe server on port 8080 -http*/

	int single_flags = 0;

	for(int i = 1; i < argc; ++i ){
		if(*argv[i] == '-') single_flags++;
	}
	
	if(single_flags == 1){
		if(argv[1][0] != '-') return -1;
		size_t sz = strlen(&argv[1][1]);
		if(sz  == strlen("s")){
			if(strncmp(&argv[1][1],"s",sz) == 0){
				inst[SECURE] = SECURE;	
			}else if(strncmp(&argv[1][1],"c",sz) == 0){
				if(argc - 1	< 2) return -1;
				inst[CLIENT] = CLIENT;
			}else if(strncmp(&argv[1][1],"l",sz) == 0){
				inst[DOMAIN] = DOMAIN;
				uint64_t doms = (uint64_t)domains;
				if(init_domains(argv,doms) == -1){
					printf("cannot initialized domains\n");
					return -1;
				}
			}else{ 
				return -1;
			}
		} else if( sz == strlen("psl")){
			if(strncmp(&argv[1][1],"psl",sz) == 0
			 	|| strncmp(&argv[1][1],"spl",sz) == 0 ){
				inst[PROD] = PROD;	
				inst[SECURE] = SECURE;
				inst[DOMAIN] = DOMAIN;
				uint64_t doms = (uint64_t)domains;
				if(init_domains(argv,doms) == -1){
					printf("cannot initialized domains\n");
					return -1;
				}
			}else{
				return -1;
			}
		}else if(sz == strlen("sl")){
			if(strncmp(&argv[1][1],"sl",sz) == 0){
				inst[DOMAIN] = DOMAIN;
				inst[SECURE] = SECURE;
				uint64_t doms = (uint64_t)domains;
				if(init_domains(argv,doms) == -1){
					printf("cannot initialized domains\n");
					return -1;
				}
			} else if(strncmp(&argv[1][1],"cg",sz) == 0){
				inst[CLIENT] = CLIENT;
				argv[1][0] = '-';
				argv[1][1] = 'g';
				argv[1][2] = '\0';
			} else if(strncmp(&argv[1][1],"pl",sz) == 0){
				inst[DOMAIN] = DOMAIN;
				inst[PROD] = PROD;
				uint64_t doms = (uint64_t)domains;
				if(init_domains(argv,doms) == -1){
					printf("cannot initialized domains\n");
					return -1;
				}
			}else{
				return -1;
			}
		}else{
			return -1;
		}
	}else{
		return -1;
	}

 	return 0;
}


static int init_domains(char ** argv,uint64_t doms)
{
	char ***domains = (char***)(doms & ADDR_MASK); 	
	int domain_count = 0;
	/*init the domains*/	
	char *p = argv[2];
	if(!p) return -1;
	char *end = NULL;
	while((end = strchr(p,','))){
		p = end + 1;
		domain_count++;
	}
	domain_count++;
	if(domain_count > (uint16_t)0xFFFF) return -1;
	*domains = (char**)malloc(sizeof(char*) * domain_count);
	if(!(*domains)) return -1;

	int k = 0;
	p = argv[2];
	while(k < domain_count && (end = strchr(p,','))){
		int dl = end - p;
		(*domains)[k] = (char*)malloc(dl + 1);
		if(!((*domains)[k])) goto clean;
		memset((*domains)[k],0,dl+1);
		memcpy((*domains)[k],argv[2],dl);
		p = end + 1;
		k++;
	}
	size_t l = strlen(p);
	(*domains)[k] = (char*)malloc(l + 1);
	if(!(*domains)[k]) goto clean;
	memset((*domains)[k],0,l+1);
	memcpy((*domains)[k],p,l);
	*domains = (char**)((uint64_t)(*domains) | ((uint64_t)domain_count << 48));
	return 0;
	
clean:
	free_domains(*domains,domain_count);
	return -1;
}

static void free_domains(char **domains,int domain_count){
	for(int i = 0; i < domain_count; i++)
		free(*(domains + i));
	free(domains);
}
