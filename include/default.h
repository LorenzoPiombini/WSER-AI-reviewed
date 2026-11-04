#ifndef _DEFAULT_H_
#define _DEFAULT_H_

#include "limits.h"

#define MAX_FILE_ON_STACK 1024
extern char certificates_path[PATH_MAX];
extern char server_log_file[PATH_MAX];
extern char dir[PATH_MAX];

#define DEF_DIR_L 5
#define DEF_DIR "/www"
#define DEF_DIR_no_su "./www"
#define INDEX_FILE_no_su "www/index.html"
#define INDEX_FILE "/www/index.html"
#define AUTO_CERT_RENEWAL ".well-known/acme-challenge/"

/*TODO: this needs to be implemented as config parameter*/
#define REDIRECT_DEFAULT_DOMAIN "https://lorenzopiombini.com"

/*the server support 10 domains by default*/
#define DOMAINS_STACK 10

#define INDEX_CNT "<!doctype html>\n<html>\n<head>\n<title>Wser</title>\n</head>\n\t<body>\n\t\t<h1>Wser home</h1>\n\t\t<h3>plug & play server</h3>\n\t</body>\n</html>\n" 
#define NOT_FOUND "<!doctype html>\n<html>\n<head>\n<title>Wser</title>\n</head>\n\t<body>\n\t\t<h1>NOT FOUND</h1>\n\t\t\t<h3>------</h3>\n\t\t<a href=\"/\">home</a>\n\t</body>\n</html>\n" 

int check_default_setting();
#endif
