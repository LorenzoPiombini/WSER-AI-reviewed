#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include "handlesig.h"

int hdl_sock = -1;
int ssl_sock = -1;
int db_sock = -1;
int http_sock = -1;
volatile sig_atomic_t reload_certificate = 0;
pid_t db_proc = -1;
pid_t ssl_proc = -1;
pid_t http_proc = -1;
static pid_t server_parent = -1;

static void terminate_process(int signo)
{
    /* No stdio, allocator, OpenSSL, epoll bookkeeping, or stale PID lists here.
     * The kernel closes descriptors and terminates our attached children. */
    _exit(128 + signo);
}

static void request_certificate_reload(int signo)
{
    (void)signo;
    reload_certificate = 1;
}

static int install_handlers(int tls)
{
    struct sigaction act = {0};
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGINT);
    sigaddset(&act.sa_mask, SIGTERM);
    act.sa_handler = terminate_process;
    if(sigaction(SIGINT, &act, NULL) || sigaction(SIGTERM, &act, NULL)) return -1;
    /* A disconnected peer is an I/O failure, not a server shutdown request. */
    act.sa_handler = SIG_IGN;
    if(sigaction(SIGPIPE, &act, NULL)) return -1;
    act.sa_handler = tls ? request_certificate_reload : SIG_IGN;
    if(sigaction(SIGHUP, &act, NULL)) return -1;
    /* Keep exited children waitable, preventing PID reuse before reaping. */
    act.sa_handler = SIG_DFL;
    if(sigaction(SIGCHLD, &act, NULL)) return -1;
    return 0;
}

int handle_sig_main_process(void) { return install_handlers(0); }
int handle_sig_http_process(void) { return install_handlers(0); }
int handle_sig_ssl_process(void) { return install_handlers(1); }
int handle_sig_db_process(void) { return install_handlers(0); }

pid_t server_fork(void)
{
    pid_t parent = getpid();
    pid_t child = fork();
    if(child == 0){
        server_parent = parent;
        /* Linux clears this setting at every fork: arm it in EVERY child.
         * SIGKILL also covers a blocked worker or a parent killed with -9. */
        if(prctl(PR_SET_PDEATHSIG, (long)SIGKILL, 0L, 0L, 0L) == -1)
            _exit(125);
        /* Parent may have exited between fork and prctl. Never attach to init. */
        if(getppid() != parent) _exit(125);
    }
    return child;
}

int signal_server_process(pid_t pid, int signo)
{
    /* Reject init, process groups, and the broadcast sentinel, even on error paths. */
    if(pid <= 1){ errno = EINVAL; return -1; }
    return kill(pid, signo);
}

int signal_server_parent(int signo)
{
    if(server_parent <= 1 || getppid() != server_parent){ errno = ESRCH; return -1; }
    return signal_server_process(server_parent, signo);
}

int server_child_running(pid_t pid)
{
    if(pid <= 1) return 0;
    int status;
    pid_t result;
    do { result = waitpid(pid, &status, WNOHANG); } while(result < 0 && errno == EINTR);
    return result == 0;
}
