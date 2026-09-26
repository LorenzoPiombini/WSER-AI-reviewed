#ifndef _MONITOR_H_
#define _MONITOR_H_

#define MAX_EVENTS 10
/* Separate interruptions from all possible positive event counts. */
#define MONITOR_INTERRUPTED (-2)

#include <sys/epoll.h>

extern struct epoll_event ev;
extern struct epoll_event events[MAX_EVENTS];
extern int nfds;
extern int epollfd;

int start_monitor(int sock);
int monitor_events(int timer);
int add_socket_to_monitor(int sock, int event);
int remove_socket_from_monitor(int sock);
int modify_monitor_event(int sock, int event);
void stop_monitor();
#endif

