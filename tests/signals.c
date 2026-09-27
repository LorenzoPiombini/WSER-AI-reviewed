#define _GNU_SOURCE
#include <assert.h>
#include <stdarg.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include "handlesig.h"

static int delay_arm;
static int race_gate[2];
int __real_prctl(int option, ...);
int __wrap_prctl(int option, ...)
{
    va_list ap;
    va_start(ap, option);
    long a=va_arg(ap,long), b=va_arg(ap,long), c=va_arg(ap,long), d=va_arg(ap,long);
    va_end(ap);
    if(option == PR_SET_PDEATHSIG && delay_arm){
        close(race_gate[1]);
        char byte;
        assert(read(race_gate[0], &byte, 1) == 0); /* parent has exited */
        close(race_gate[0]);
    }
    return __real_prctl(option, a, b, c, d);
}

static void startup_race_test(void)
{
    int report[2];
    assert(pipe(race_gate) == 0 && pipe(report) == 0);
    pid_t parent=fork(); assert(parent>=0);
    if(parent==0){
        close(report[0]);
        assert(handle_sig_main_process()==0);
        delay_arm=1;
        pid_t child=server_fork();
        assert(child>=0);
        if(child==0) _exit(99); /* must not reach worker code */
        assert(write(report[1], &child, sizeof(child))==sizeof(child));
        _exit(0);
    }
    close(report[1]); close(race_gate[0]); close(race_gate[1]);
    pid_t child; assert(read(report[0], &child, sizeof(child))==sizeof(child)); close(report[0]);
    assert(waitpid(parent,NULL,0)==parent);
    int status; assert(waitpid(child,&status,0)==child);
    assert(WIFEXITED(status) && WEXITSTATUS(status)==125);
}

static void ready(int fd)
{
    pid_t pid = getpid();
    assert(write(fd, &pid, sizeof(pid)) == sizeof(pid));
}
static void idle(void) { for(;;) pause(); }

/* Same topology as ./db s, plus one request child under each HTTP/TLS worker. */
static void tree(int reports, int control, int listener)
{
    assert(handle_sig_main_process() == 0);
    pid_t tls = server_fork();
    assert(tls >= 0);
    if(tls == 0){
        close(listener);
        assert(handle_sig_ssl_process() == 0);
        pid_t db = server_fork();
        assert(db >= 0);
        if(db == 0){ assert(handle_sig_db_process() == 0); ready(reports); idle(); }
        pid_t request = server_fork();
        assert(request >= 0);
        if(request == 0){ ready(reports); idle(); }
        ready(reports); idle();
    }
    pid_t http = server_fork();
    assert(http >= 0);
    if(http == 0){
        close(listener);
        assert(handle_sig_http_process() == 0);
        pid_t request = server_fork();
        assert(request >= 0);
        if(request == 0){ ready(reports); idle(); }
        ready(reports); idle();
    }
    ready(reports);
    char command;
    assert(read(control, &command, 1) == 1);
    _exit(0); /* also test ordinary main exit */
}

static void shutdown_test(int signo, int all)
{
    int reports[2], control[2];
    assert(pipe(reports) == 0 && pipe(control) == 0);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(listener, 1) == 0);
    socklen_t length = sizeof(addr);
    assert(getsockname(listener, (struct sockaddr *)&addr, &length) == 0);
    pid_t main_pid = fork();
    assert(main_pid >= 0);
    if(main_pid == 0){ close(reports[0]); close(control[1]); tree(reports[1], control[0], listener); _exit(1); }
    close(listener); close(reports[1]); close(control[0]);
    pid_t members[6];
    for(int i=0;i<6;++i){
        struct pollfd p = {.fd=reports[0],.events=POLLIN};
        assert(poll(&p, 1, 3000) == 1);
        assert(read(reports[0], &members[i], sizeof(pid_t)) == sizeof(pid_t));
        assert(members[i] > 1);
    }
    if(!signo) assert(write(control[1], "q", 1) == 1);
    else if(all){
        /* Equivalent delivery to matching workers, without a broad pkill. */
        for(int i=0;i<6;++i) {
            int r=kill(members[i], signo); assert(r==0 || errno==ESRCH);
        }
    } else assert(kill(main_pid, signo) == 0);
    close(control[1]); close(reports[0]);
    int reaped = 0;
    for(int attempt=0; attempt<300 && reaped<6; ++attempt){
        for(int i=0;i<6;++i){
            if(members[i] <= 0) continue;
            int status;
            pid_t r=waitpid(members[i], &status, WNOHANG);
            if(r==members[i]){ members[i]=0; ++reaped; }
            else assert(r==0 || (r==-1 && errno==ECHILD)); /* not adopted yet */
        }
        if(reaped<6) poll(NULL,0,10);
    }
    if(reaped != 6){
        for(int i=0;i<6;++i) if(members[i]>1) kill(members[i], SIGKILL);
    }
    assert(reaped == 6);
    listener=socket(AF_INET, SOCK_STREAM, 0);
    assert(listener>=0 && bind(listener, (struct sockaddr *)&addr, sizeof(addr))==0);
    close(listener);
}

static void handler_test(int (*setup)(void), int tls)
{
    int report[2]; assert(pipe(report)==0);
    pid_t pid=fork(); assert(pid>=0);
    if(pid==0){
        close(report[0]);
        assert(setup()==0);
        raise(SIGPIPE); /* must remain alive */
        raise(SIGHUP);
        assert(reload_certificate == tls);
        ready(report[1]); idle();
    }
    close(report[1]); pid_t child;
    struct pollfd p={.fd=report[0],.events=POLLIN}; assert(poll(&p,1,3000)==1);
    assert(read(report[0],&child,sizeof(child))==sizeof(child)); close(report[0]);
    assert(kill(pid,SIGTERM)==0);
    int status; assert(waitpid(pid,&status,0)==pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status)==128+SIGTERM);
}

int main(void)
{
    /* Adopt grandchildren so this test can prove they exited and reap them. */
    assert(prctl(PR_SET_CHILD_SUBREAPER, 1L, 0L, 0L, 0L)==0);
    assert(signal_server_process(-1,SIGTERM)==-1 && errno==EINVAL);
    assert(signal_server_process(0,SIGTERM)==-1 && errno==EINVAL);
    assert(signal_server_process(1,SIGTERM)==-1 && errno==EINVAL);
    assert(signal_server_parent(SIGTERM)==-1 && errno==ESRCH);
    startup_race_test();
    handler_test(handle_sig_main_process,0);
    handler_test(handle_sig_http_process,0);
    handler_test(handle_sig_db_process,0);
    handler_test(handle_sig_ssl_process,1);
    /* An unrelated process must survive all shutdown modes. */
    pid_t unrelated=fork(); assert(unrelated>=0);
    if(unrelated==0) idle();
    for(int i=0;i<3;++i){
        shutdown_test(SIGTERM,0);
        shutdown_test(SIGINT,0);
        shutdown_test(SIGKILL,0);
        shutdown_test(0,0);
        shutdown_test(SIGTERM,1);
        assert(kill(unrelated,0)==0);
    }
    assert(!server_child_running(getpid())); /* not a direct child */
    assert(kill(unrelated,SIGKILL)==0); assert(waitpid(unrelated,NULL,0)==unrelated);
    puts("Signal tests passed: all roles, subtree shutdown, port release, unrelated process isolation");
}
