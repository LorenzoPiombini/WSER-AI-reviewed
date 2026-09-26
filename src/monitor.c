#include <stdio.h>  
#include <sys/epoll.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "monitor.h"

static char prog[] = "wser"; 


struct epoll_event ev;
struct epoll_event events[MAX_EVENTS];
int epollfd = -1;
int nfds = -1;


#define MAX_SK_LIST 256
static int sock_list[MAX_SK_LIST];
static int look_for_free_index();
static int find_sock(int sock);
static int free_socket_list(int sock);


int start_monitor(int sock)
{
	int newfd = epoll_create1(EPOLL_CLOEXEC);
	if (newfd == -1){
		fprintf(stderr,"(%s): failed to initialize monitor, %s:%d.\n",prog,__FILE__,__LINE__);
		return -1;
	}

    if(epollfd >= 0) close(epollfd);
    epollfd = newfd;
    memset(sock_list, -1, sizeof(sock_list));
    if(add_socket_to_monitor(sock, EPOLLIN) == -1){
        int error = errno;
        stop_monitor();
        errno = error;
        return -1;
    }

	return 0;
}

int monitor_events(int timer)
{
	errno = 0;
	nfds = epoll_wait(epollfd, events, MAX_EVENTS, timer);
	if(nfds == -1){
		if(errno == EINTR) return MONITOR_INTERRUPTED;
		fprintf(stderr,"(%s): epoll_wait() failed %s:%d.\n",prog,__FILE__,__LINE__);
		return -1;
	}
	if(nfds == 0){
		fprintf(stderr,"(%s): timer expired! %s:%d.\n",prog,__FILE__,__LINE__);
		return -1;
	}
	return nfds;
}

int add_socket_to_monitor(int sock,int event)
{
	
	if(sock < 0 || epollfd < 0){ errno = EBADF; return -1; }
    if(find_sock(sock) == 0) return modify_monitor_event(sock, event);
	int index = -1;

	if(find_sock(sock) == -1){
		index = look_for_free_index();

		if(index == -1) return -1; /* think about this line */

		sock_list[index] = sock;
	}
		
	errno = 0;
	ev.events = event;
	ev.data.fd = sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &ev) == -1) {
		if(errno == EEXIST) {
			if(index != -1)
				sock_list[index] = -1;
			return errno;
		}

		if(index != -1)
			sock_list[index] = -1;

        	fprintf(stderr,"(%s): cannot add socket to monitor",prog);
		return -1;
	}


	return 0;
}

int remove_socket_from_monitor(int sock)
{

	errno = 0;
	if (epoll_ctl(epollfd, EPOLL_CTL_DEL, sock,NULL) == -1) {
               fprintf(stderr,"(%s): cannot remove socket from monitor: %s\n",prog,strerror(errno));
	       if (free_socket_list(sock) == -1) {
		       fprintf(stderr,"(%s):socket %d not found in list.\n",prog,sock);
		       return -1;
	       }
               return -1;
	}

	if (free_socket_list(sock) == -1) {
		fprintf(stderr,"(%s):socket %d not found in list.\n",prog,sock);
		return -1;
	}

	return 0;
}

int modify_monitor_event(int sock, int event)
{
	ev.events = event;
	ev.data.fd = sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_MOD, sock, &ev) == -1) {
               fprintf(stderr,"(%s): cannot modify socket event in the monitor",prog);
               return -1;
	}
	

	return 0;
}

void stop_monitor()
{
    if(epollfd >= 0) close(epollfd);
    epollfd = -1;
    memset(sock_list, -1, sizeof(sock_list));
}

int is_sock_in_monitor(int sock){
	for(int i = 0; i < MAX_SK_LIST; i++)
		if(sock_list[i] == sock) return 1;

	return 0;
}
static int look_for_free_index()
{
	for(int i = 0; i < MAX_SK_LIST; i++)
		if(sock_list[i] == -1) return i;

	return -1;
}

static int free_socket_list(int sock)
{
	for(int i = 0; i < MAX_SK_LIST; i++){
		if (sock_list[i] == sock) {
			sock_list[i] = -1;
			return 0;
		}
	}
	return -1;
}

static int find_sock(int sock){
	int i;
	for(i = 0; i < MAX_SK_LIST; i++)
		if(sock_list[i] == sock) return 0;

	return -1;
}
