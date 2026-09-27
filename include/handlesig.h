#ifndef _HANDLESIG_H_
#define _HANDLESIG_H_ 1


#include <sys/types.h>
#include <signal.h>

extern volatile sig_atomic_t reload_certificate;
extern int hdl_sock; 
extern int ssl_sock;
extern int db_sock;
extern int http_sock;
extern pid_t ssl_proc; 
extern pid_t db_proc; 
extern pid_t http_proc;

int handle_sig_main_process();
int handle_sig_ssl_process();
int handle_sig_http_process();
int handle_sig_db_process();

/* Use for all server forks so parent exit terminates the complete subtree. */
pid_t server_fork(void);
int signal_server_process(pid_t pid, int signo);
int signal_server_parent(int signo);
/* Reaps an exited direct child; never probes unrelated/reused PIDs. */
int server_child_running(pid_t pid);

#endif
