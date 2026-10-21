#ifndef _OS_OPERATIONS_H
#define _OS_OPERATIONS_H

#if defined(__linux__) || defined(__APPLE__)
	#define PATH_OS "/"
#elif defined(_WIN32) || defined(_WIN64)
	#define PATH_OS "\\"
#endif

#include <stdint.h>
int make_dir(char * dir_name);
int create_folder(char *file_name);
int change_dir(char* dir_name);
int write_file(char *compressed_file_name,uint8_t *data, uint64_t size);
long long read_file(char *file_name, uint8_t **file_content);

#endif
