#ifndef __LOAD_H_
#define __LOAD_H_

#include "request.h"
#define MAX_CONT_SZ 5000
struct Content{
	char cnt_st[MAX_CONT_SZ];
	char *cnt_dy;
	size_t size;
};


#define GZ_HEADER 700
int load_resource(char *rpath, struct Content *cont, int gzip);
void clear_content(struct Content *cont);

#ifdef OWN_DB
int load_resource_db(struct Request *req, struct Content *cont,int data_sock);
#endif

#endif
