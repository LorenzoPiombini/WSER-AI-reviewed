# Wser - HTTP server 

the idea is to have an http server plug and play, no configurations need it, at least for development.  
the server uses NON-BLOCKING sockets and the events on the sockets file descriptor are monitored   
with EPOLL, which is platform specific,so this version of Wser is for Linux only .

if you dont have root privileges the program will try  
to listen on port 8080, if you run wser with super user privileges it will listen  
to incoming connections to port 80.

a message stating the port where the server is listening to will be displaied to  the console.

based on your user permission wser will create a www directory, if yiu are root it will be at the '/' level whereas if you are running the program   
as a regular user the www directory will be placed on your home directory. 

to serve the website you have to put your .html .css .js images and so on inside the www directory. 

upon first execution wser will place a very basic index.html file inside ./www 
## Base HTTP version supported
---
HTTP/1.1 is the default version.




## Build and regression tests

The standalone server requires Linux, a C compiler, Make, and the OpenSSL
headers/libraries. Run `make` to build `wser`, and `make test` to run the JSON,
HTTP, and TLS regression checks. The TLS test generates a temporary self-signed
certificate under `obj/`; it does not use the server's configured certificate.

AddressSanitizer and UndefinedBehaviorSanitizer are enabled by default. In
containers where LeakSanitizer cannot inspect processes, use
`ASAN_OPTIONS=detect_leaks=0 make test`; this still runs the address and undefined
behavior checks. For a build without sanitizers, run
`make clean && make SANITIZERS=`. Run `make db` only when the separate database
headers and libraries are installed; it uses its own object directory.

Requests have a 16 KiB header limit and a 1 MiB total size limit. HTTP/1.0 and
HTTP/1.1 Content-Length framing are supported; Transfer-Encoding requests are
rejected because chunked request decoding is not implemented. Each connection
serves one request and then closes. JSON parsing continues to require an object
or array at the root. `decode_json_escape` writes raw bytes without appending a
terminator, returns 0 on success / -1 on error, and supports UTF-16 surrogate
pairs in escapes.

See `REVIEW.md` for the fixes and validation boundaries of this review.
