#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "network.h"
#include "monitor.h"

int main(int argc, char **argv)
{
    assert(argc == 3);
    SSL_CTX *server = SSL_CTX_new(TLS_server_method());
    SSL_CTX *client = SSL_CTX_new(TLS_client_method());
    assert(server && client);
    assert(SSL_CTX_use_certificate_file(server, argv[1], SSL_FILETYPE_PEM) == 1);
    assert(SSL_CTX_use_PrivateKey_file(server, argv[2], SSL_FILETYPE_PEM) == 1);
    SSL_CTX_set_verify(client, SSL_VERIFY_NONE, NULL);
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0);
    assert(start_monitor(fd[0]) == 0);
    struct Connection_data cd[MAX_CON_DAT_ARR] = {0};
    cd[0].fd = fd[0];
    cd[0].ssl = SSL_new(server);
    SSL *peer = SSL_new(client);
    assert(cd[0].ssl && peer);
    assert(SSL_set_fd(cd[0].ssl, fd[0]) == 1);
    assert(SSL_set_fd(peer, fd[1]) == 1);
    struct Request req = {0};
    for(int i = 0; i < 10000; ++i){
        int result = SSL_connect(peer);
        if(result != 1){
            int err = SSL_get_error(peer, result);
            assert(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE);
        }
        int status = read_cli_sock_SSL(fd[0], &req, cd);
        assert(status == HANDSHAKE || status == SSL_READ_E);
        if(SSL_is_init_finished(peer) && SSL_is_init_finished(cd[0].ssl)) break;
    }
    assert(SSL_is_init_finished(peer) && SSL_is_init_finished(cd[0].ssl));
    const char *h = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9000\r\n\r\n";
    for(size_t i = 0; i < strlen(h); ++i){
        size_t n;
        assert(SSL_write_ex(peer, h + i, 1, &n) == 1 && n == 1);
        assert(read_cli_sock_SSL(fd[0], &req, cd) == SSL_READ_E);
    }
    char body[9000];
    for(size_t i = 0; i < sizeof(body); ++i) body[i] = (char)i;
    size_t n;
    assert(SSL_write_ex(peer, body, 3000, &n) == 1 && n == 3000);
    assert(read_cli_sock_SSL(fd[0], &req, cd) == SSL_READ_E);
    assert(SSL_write_ex(peer, body + 3000, 6000, &n) == 1 && n == 6000);
    assert(read_cli_sock_SSL(fd[0], &req, cd) == 0);
    assert(req.req_body.size == sizeof(body) && !memcmp(req.req_body.d_cont, body, sizeof(body)));
    clear_request(&req);

    int small = 1024;
    assert(setsockopt(fd[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
    struct Response res = {0};
    strcpy(res.header_str, "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n");
    res.body.size = 100000;
    res.body.d_cont = malloc(res.body.size);
    for(size_t i = 0; i < res.body.size; ++i) res.body.d_cont[i] = (char)i;
    size_t header_size = strlen(res.header_str), total = header_size + res.body.size;
    char *expected = malloc(total), *received = malloc(total);
    memcpy(expected, res.header_str, header_size);
    memcpy(expected + header_size, res.body.d_cont, res.body.size);
    assert(write_cli_SSL(fd[0], &res, cd) == SSL_WRITE_E);
    clear_response(&res); /* pending TLS output must own its bytes */
    size_t got = 0;
    int done = 0;
    for(int i = 0; i < 10000 && got < total; ++i){
        int result = SSL_read_ex(peer, received + got, total - got, &n);
        if(result == 1) got += n;
        else {
            int err = SSL_get_error(peer, result);
            assert(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE);
        }
        if(!done){
            int status = write_cli_SSL(fd[0], NULL, cd);
            assert(status == 0 || status == SSL_WRITE_E);
            done = status == 0;
        }
    }
    assert(done && got == total && !memcmp(expected, received, total));
    free(expected); free(received);
    clean_connecion_data(cd, fd[0]);
    stop_monitor();
    SSL_free(peer);
    SSL_CTX_free(server); SSL_CTX_free(client);
    close(fd[0]); close(fd[1]);
    puts("TLS fragmented input and binary retry checks passed");
}
