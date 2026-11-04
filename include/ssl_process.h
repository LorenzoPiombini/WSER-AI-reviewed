#ifndef _SSL_PROCESS_H_
#define _SSL_PROCESS_H_ 1


#include <openssl/ssl.h>
#include <stdint.h>

struct SNI_config{
	char **domains;
	SSL_CTX **ctxs;
	int domain_count;
};
int SSL_work_process(int data_sock, uint64_t domains);
#endif 
