#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <time.h>
#include "network.h"
#include "monitor.h"
#include "load.h"


/* Use a temporary document root, even when tests execute as root. */
uid_t __wrap_getuid(void) { return 1000; }
static void alarm_handler(int sig) { (void)sig; }

static void monitor_tests(void)
{
    int pairs[4][2];
    for(int i=0;i<4;++i) assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pairs[i]) == 0);
    assert(start_monitor(pairs[0][0]) == 0);
    for(int i=1;i<4;++i) assert(add_socket_to_monitor(pairs[i][0], EPOLLIN) == 0);
    for(int i=0;i<4;++i) assert(write(pairs[i][1], "x", 1) == 1);
    assert(monitor_events(100) == 4); /* must not be mistaken for EINTR */
    for(int i=0;i<4;++i){ char b; assert(read(pairs[i][0], &b, 1) == 1); }
    struct sigaction sa = {0};
    sa.sa_handler = alarm_handler;
    assert(sigaction(SIGALRM, &sa, NULL) == 0);
    struct itimerval timer = {.it_value = {.tv_usec = 10000}};
    assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    assert(monitor_events(-1) == MONITOR_INTERRUPTED);
    assert(add_socket_to_monitor(pairs[0][0], EPOLLIN) == 0);
    int old = epollfd;
    assert(start_monitor(pairs[0][0]) == 0);
    assert(fcntl(old, F_GETFD) == -1 && errno == EBADF);
    stop_monitor();
    int fd = open("/dev/null", O_RDONLY);
    assert(fd >= 0);
    stop_monitor(); /* must not close an unrelated reused descriptor */
    assert(fcntl(fd, F_GETFD) != -1);
    close(fd);
    for(int i=0;i<4;++i){ close(pairs[i][0]); close(pairs[i][1]); }
}

/* The execution sandbox blocks SOCK_SEQPACKET setup. Wrap only the Unix
 * transport syscalls; use real descriptors to check flags and failure cleanup. */
static int last_socket = -1;
static int fail_bind, fail_listen;
int __wrap_socket(int family, int type, int protocol)
{
    assert(family == AF_UNIX && protocol == 0);
    assert((type & ~(SOCK_NONBLOCK|SOCK_CLOEXEC)) == SOCK_SEQPACKET);
    int p[2];
    if(socketpair(AF_UNIX, SOCK_STREAM | (type & (SOCK_NONBLOCK|SOCK_CLOEXEC)), 0, p)) return -1;
    close(p[1]);
    return last_socket = p[0];
}
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t n)
{
    assert(fd == last_socket && addr->sa_family == AF_UNIX && n == sizeof(struct sockaddr_un));
    if(fail_bind){ errno = EADDRINUSE; return -1; }
    return 0;
}
int __wrap_listen(int fd, int n)
{
    assert(fd == last_socket && n > 0);
    if(fail_listen){ errno = EIO; return -1; }
    return 0;
}
int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t n)
{
    assert(fd == last_socket && addr->sa_family == AF_UNIX && n == sizeof(struct sockaddr_un));
    errno = ECONNREFUSED;
    return -1;
}
int __wrap_accept4(int fd, struct sockaddr *addr, socklen_t *n, int flags)
{
    (void)fd; (void)addr; (void)n; (void)flags;
    errno = EAGAIN;
    return -1;
}

static void unix_tests(void)
{
    char name[] = "/tmp/wser-infra-XXXXXX";
    assert(mkdtemp(name));
    char path[256];
    snprintf(path, sizeof(path), "%s/ipc", name);
    int fd = listen_UNIX_socket(SOCK_NONBLOCK, path);
    assert(fd >= 0);
    assert(fcntl(fd, F_GETFL) & O_NONBLOCK);
    assert(fcntl(fd, F_GETFD) & FD_CLOEXEC);
    int client;
    struct Request req = {0};
    assert(wait_for_connections(fd, &client, &req, MULTI_PROC) == EAGAIN);
    assert(wait_for_connections_SSL(fd, &client) == EAGAIN);
    close(fd); unlink(path);
    assert(connect_UNIX_socket(0, path) == -1 && errno == ECONNREFUSED);
    assert(fcntl(last_socket, F_GETFD) == -1 && errno == EBADF);
    fail_bind = 1;
    assert(listen_UNIX_socket(0, path) == -1 && errno == EADDRINUSE);
    assert(fcntl(last_socket, F_GETFD) == -1 && errno == EBADF);
    fail_bind = 0; fail_listen = 1;
    assert(listen_UNIX_socket(0, path) == -1 && errno == EIO);
    assert(fcntl(last_socket, F_GETFD) == -1 && errno == EBADF);
    fail_listen = 0;
    int regular = open(path, O_CREAT|O_EXCL|O_WRONLY, 0600);
    assert(regular >= 0); close(regular);
    assert(listen_UNIX_socket(SOCK_NONBLOCK, path) == -1);
    struct stat st;
    assert(stat(path, &st) == 0 && S_ISREG(st.st_mode));
    unlink(path); rmdir(name);
    char longpath[256];
    memset(longpath, 'x', sizeof(longpath)-1); longpath[255] = 0;
    assert(connect_UNIX_socket(0, longpath) == -1 && errno == ENAMETOOLONG);
    assert(listen_UNIX_socket(0, longpath) == -1 && errno == ENAMETOOLONG);
}

static int short_reads, interrupted_read;
ssize_t __real_read(int fd, void *buf, size_t count);
ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    if(short_reads){
        if(!interrupted_read++){ errno = EINTR; return -1; }
        if(count > 1) count = 1;
    }
    return __real_read(fd, buf, count);
}

static void file_tests(void)
{
    char name[] = "/tmp/wser-files-XXXXXX";
    int cwd = open(".", O_RDONLY|O_DIRECTORY);
    assert(cwd >= 0 && mkdtemp(name));
    assert(chdir(name) == 0 && mkdir("www",0700) == 0);
    int fd = open("www/a b.bin", O_CREAT|O_WRONLY|O_EXCL,0600);
    assert(fd >= 0 && write(fd,"a\0b",3) == 3); close(fd);
    fd = open("www/index.html", O_CREAT|O_WRONLY|O_EXCL,0600);
    assert(fd >= 0 && write(fd,"home",4) == 4); close(fd);
    struct Content c = {0};
    short_reads = 1;
    assert(load_resource("/a%20b.bin?v=2", &c) == 0);
    short_reads = 0;
    assert(c.size == 3 && !memcmp(c.cnt_st,"a\0b",3)); clear_content(&c);
    assert(load_resource("/?v=2", &c) == 0 && c.size == 4); clear_content(&c);
    const char *invalid[] = {"/%2e%2e/index.html", "/%00", "/bad%", "/bad%xy", NULL};
    for(int i=0;invalid[i];++i){
        assert(load_resource((char *)invalid[i], &c) == -1); clear_content(&c);
    }
    assert(symlink("index.html", "www/link") == 0);
    assert(load_resource("/link", &c) == -1); clear_content(&c);
    assert(mkfifo("www/pipe",0600) == 0);
    struct timespec start, end;
    assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    alarm(2); /* a FIFO open must not hang waiting for a writer */
    assert(load_resource("/pipe", &c) == -1); alarm(0); clear_content(&c);
    assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    assert((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9 < 1.0);
    assert(load_resource("/", &c) == 0); clear_content(&c);
    unlink("www/pipe"); unlink("www/link"); unlink("www/index.html"); unlink("www/a b.bin");
    rmdir("www"); assert(fchdir(cwd) == 0); close(cwd); rmdir(name);
}

int main(int argc, char **argv)
{
    if(argc==1 || !strcmp(argv[1],"monitor")) monitor_tests();
    if(argc==1 || !strcmp(argv[1],"unix")) unix_tests();
    if(argc==1 || !strcmp(argv[1],"files")) file_tests();
    puts("Monitor, Unix socket, and static-file checks passed");
}
