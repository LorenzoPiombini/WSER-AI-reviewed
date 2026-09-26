#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "request.h"
#include "response.h"
#include "network.h"
#include "json.h"

static void json_tests(void)
{
    const char *valid[] = {"{}", "[]", "[1,true,null,false]", "[{},2,[],3]", "{\"a\":{},\"b\":[]}", NULL};
    const char *invalid[] = {"", " ", "[][]", "[],", "[1{}]", "{\"a\"{}}", "{\"a\":1{}}", "[1,]", "{\"a\":", NULL};
    struct Json_token t[64];
    for (int i = 0; valid[i]; ++i) {
        memset(t, 0xa5, sizeof(t));
        assert(json_parser(valid[i], strlen(valid[i]), t, 64) > 0);
    }
    for (int i = 0; invalid[i]; ++i) {
        size_t n = strlen(invalid[i]);
        char *s = malloc(n ? n : 1); /* deliberately no terminator */
        memcpy(s, invalid[i], n);
        assert(json_parser(s, n, t, 64) == JSON_INVALID_ERR);
        free(s);
    }
    assert(json_parser("{}", 2, t, 1) == 1);
    assert(json_parser("[0]", 3, t, 1) == JSON_TK_LIMIT_ERR);
    char nested[2 * (JSON_MAX_DEPTH + 1)];
    memset(nested, '[', JSON_MAX_DEPTH);
    memset(nested + JSON_MAX_DEPTH, ']', JSON_MAX_DEPTH);
    assert(json_parser(nested, 2 * JSON_MAX_DEPTH, t, 64) == JSON_MAX_DEPTH);
    memset(nested, '[', JSON_MAX_DEPTH + 1);
    memset(nested + JSON_MAX_DEPTH + 1, ']', JSON_MAX_DEPTH + 1);
    assert(json_parser(nested, sizeof(nested), t, 64) == JSON_DEPTH_LIMIT_ERR);
    uint8_t out[4];
    assert(encode_json_unicode((const uint8_t *)"12x4", out, 4, 4) == -1);
}

static int request(const char *s, size_t n, struct Request *r)
{
    memset(r, 0, sizeof(*r));
    if (n > sizeof(r->req)) {
        r->d_req = malloc(n);
        assert(r->d_req);
        memcpy(r->d_req, s, n);
    } else memcpy(r->req, s, n);
    r->size = n;
    return handle_request(r);
}

static void request_tests(void)
{
    struct Request r;
    const char *bad[] = {"GET\r\n\r\n", "GET / HTTP/1.1\r\n\r\n", "GET / HTTP/1.1\r\nX-Host: a\r\n\r\n", "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n", "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 0x\r\n\r\n", "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n", "GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n", NULL};
    for (int i = 0; bad[i]; ++i) {
        assert(request(bad[i], strlen(bad[i]), &r) == BAD_REQ);
        clear_request(&r);
    }
    const char good[] = "POST / HTTP/1.1\r\nhost:a\r\nContent-Type: application/octet-stream\r\ncontent-length: 3\r\n\r\na\0b";
    assert(request(good, sizeof(good) - 1, &r) == 0);
    assert(r.req_body.size == 3 && memcmp(r.req_body.content, "a\0b", 3) == 0);
    assert(strcmp(r.cont_type, "application/octet-stream") == 0);
    clear_request(&r);
    clear_request(&r);
    char longhost[300];
    memset(longhost, 'a', sizeof(longhost));
    memcpy(longhost, "GET / HTTP/1.1\r\nHost: ", strlen("GET / HTTP/1.1\r\nHost: "));
    memcpy(longhost + sizeof(longhost) - 4, "\r\n\r\n", 4);
    assert(request(longhost, sizeof(longhost), &r) == BAD_REQ);
    clear_request(&r);
    size_t n = 9000;
    char *large = malloc(n + 100);
    int h = sprintf(large, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: %zu\r\n\r\n", n);
    memset(large + h, 'x', n);
    assert(request(large, h + n, &r) == 0);
    assert(r.req_body.d_cont && r.req_body.size == n);
    assert(memcmp(r.req_body.d_cont, large + h, n) == 0);
    clear_request(&r);
    free(large);
    char *shortbuf = malloc(3);
    memcpy(shortbuf, "GET", 3);
    assert(find_headers_end(shortbuf, 3) == -1);
    free(shortbuf);
}

static void response_tests(void)
{
    struct Request q = {0};
    struct Response r = {0};
    struct Content c = {0};
    strcpy(q.cont_type, "application/octet-stream");
    memcpy(c.cnt_st, "a\0b", 3);
    c.size = 3;
    assert(generate_response(&r, 200, &c, &q) == 0);
    assert(memcmp(r.body.content, "a\0b", 3) == 0);
    int s[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, s) == 0);
    size_t h = strlen(r.header_str);
    assert(write_cli_sock(s[0], &r) == 0);
    char buf[2048];
    assert(read(s[1], buf, sizeof(buf)) == (ssize_t)(h + 3));
    assert(memcmp(buf + h, "a\0b", 3) == 0);
    close(s[0]); close(s[1]);
    clear_response(&r);
    assert(generate_response(&r, 500, NULL, &q) == 0);
    assert(strstr(r.header_str, "Content-Length:") != NULL);
    clear_response(&r);
    q.method = OPTIONS;
    assert(generate_response(&r, 200, NULL, &q) == 0);
    assert(strstr(r.header_str, "\r\n\r\n") != NULL);
    clear_response(&r);
}

static void decoder_tests(void)
{
    char out[16];
    memset(out, 0x55, sizeof(out));
    assert(decode_json_escape("abc", 3, out, sizeof(out)) == 0);
    assert(!memcmp(out, "abc", 3) && out[3] == 0x55);
    assert(decode_json_escape("\\n", 2, out, 1) == 0 && out[0] == '\n');
    assert(decode_json_escape("\\u0000", 6, out, 1) == 0 && out[0] == 0);
    assert(decode_json_escape("\\uD83D\\uDE00", 12, out, 4) == 0);
    assert(!memcmp(out, "\xf0\x9f\x98\x80", 4));
    const char *bad[] = {"\\", "\\x", "\\u12", "\\u12xz", "\\uD800", "\\uDC00", "\\uD800\\u0041", NULL};
    for(int i = 0; bad[i]; ++i){
        size_t n = strlen(bad[i]);
        char *raw = malloc(n);
        memcpy(raw, bad[i], n);
        assert(decode_json_escape(raw, n, out, sizeof(out)) == -1);
        free(raw);
    }
    assert(decode_json_escape("abc", 3, out, 2) == -1);
    assert(decode_json_escape("\\u20ac", 6, out, 2) == -1);
    assert(decode_json_escape("\\uD83D\\uDE00", 12, out, 3) == -1);
}

static void socket_tests(void)
{
    int s[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, s) == 0);
    struct Request q = {0};
    const char *header = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9000\r\n\r\n";
    for(size_t i = 0; i < strlen(header); ++i){
        assert(write(s[0], header + i, 1) == 1);
        assert(read_cli_sock(s[1], &q) == EAGAIN);
    }
    char body[9000];
    for(size_t i = 0; i < sizeof(body); ++i) body[i] = (char)i;
    assert(write(s[0], body, 4000) == 4000);
    assert(read_cli_sock(s[1], &q) == EAGAIN);
    assert(write(s[0], body + 4000, 5000) == 5000);
    assert(read_cli_sock(s[1], &q) == 0);
    assert(q.req_body.size == sizeof(body));
    assert(!memcmp(q.req_body.d_cont, body, sizeof(body)));
    clear_request(&q);
    close(s[0]); close(s[1]);

    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, s) == 0);
    int small = 1024;
    assert(setsockopt(s[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
    struct Response r = {0};
    strcpy(r.header_str, "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n");
    r.body.size = 100000;
    r.body.d_cont = malloc(r.body.size);
    assert(r.body.d_cont);
    for(size_t i = 0; i < r.body.size; ++i) r.body.d_cont[i] = (char)i;
    size_t h = strlen(r.header_str), total = h + r.body.size, got = 0;
    char *received = malloc(total);
    int blocked = 0, done = 0;
    for(int i = 0; i < 10000 && got < total; ++i){
        int status = write_cli_sock(s[0], &r);
        assert(status == 0 || status == EAGAIN);
        blocked |= status == EAGAIN;
        done |= status == 0;
        ssize_t n = read(s[1], received + got, total - got);
        if(n > 0) got += n;
        else assert(n == -1 && errno == EAGAIN);
    }
    assert(blocked && done && got == total);
    assert(!memcmp(received, r.header_str, h));
    assert(!memcmp(received + h, r.body.d_cont, r.body.size));
    assert(fcntl(s[0], F_GETFL) & O_NONBLOCK);
    free(received);
    clear_response(&r);
    close(s[0]); close(s[1]);
}

int main(int argc, char **argv)
{
    if (argc == 1 || !strcmp(argv[1], "json")) json_tests();
    if (argc == 1 || !strcmp(argv[1], "request")) request_tests();
    if (argc == 1 || !strcmp(argv[1], "response")) response_tests();
    if(argc == 1) { decoder_tests(); socket_tests(); }
    puts("Regression checks passed");
}
