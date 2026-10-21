#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os_operations.h"

#if defined(__linux__) || defined(__APPLE__)
	#include <sys/stat.h>
	#include <errno.h>
	#include <unistd.h>
	
	char parent_dir[1024] = {0};
#elif defined(_WIN32) || defined(_WIN64)
	#ifndef UNICODE
	#define UNICODE
	#endif
	#include <windows.h>
	wchar_t parent_dir[1024] = {0};
#endif

static int is_path_legal(const char *p);
static int path_exist(const char *p);
static int has_slash(const char *p,int *pos);

int change_dir(char* dir_name)
{
#if defined(__linux__) || defined(__APPLE__)
	if(chdir(dir_name) == -1) return -1;
#elif defined(_WIN32) || defined(_WIN64)
	/*WINDOWS migth use wchar_t we need to convert the char * to wchar_t * */
	mbstate_t ps;
	size_t l = strlen(dir_name);
	wchar_t wstr[l+1];
	wmemset(wstr,0,l+1);

	size_t error = -1;
    if(mbsrtowcs(wstr,(const char** restrict)&dir_name,l,&ps) == -1) return -1;

	if(!SetCurrentDirectory(wstr)) return -1;
#endif
	return 0;
}
int make_dir(char * dir_name)
{

#if defined(__linux__) || defined(__APPLE__)
	if(mkdir(dir_name, S_IRWXU | S_IFDIR ) == -1) {
		if(errno != EEXIST) return -1;
	}
#elif defined(_WIN32) || defined(_WIN64)
	mbstate_t ps;
	size_t l = strlen(dir_name);
	wchar_t wstr[l+1];
	wmemset(wstr,0,l+1);

    if(mbsrtowcs(wstr,(const char ** restrict)&dir_name,l,&ps) == -1) return -1;

	if(!CreateDirectoryW(wstr,NULL)) return -1;

#endif
	return 0;

}
int create_folder(char *file_name)
{

#if defined(__linux__) || defined(__APPLE__)
	if(!parent_dir[0]){
		errno = 0;
		if(getcwd(parent_dir,1024) == NULL){
			if(errno == EINVAL){
				fprintf(stderr,"bigger buffer for directory path");
			}
			return -1;
		}
	}

	int slash_pos = 0;
	if(has_slash(file_name,&slash_pos)){
		char p[slash_pos+1];
		memset(p,0,slash_pos+1);
		strncpy(p,file_name,slash_pos);
		errno = 0;
    	if(mkdir(p, S_IRWXU | S_IFDIR ) == -1) {
			if(errno != EEXIST) return -1;
		}
		if(chdir(p) == -1) return -1;

		char *s = file_name;
		if(create_folder(s + slash_pos +1) == -1) return -1;
	}

	if(chdir(parent_dir) == -1) return -1;
#elif defined(_WIN32) || defined(_WIN64)
	if(!parent_dir[0]){
		DWORD res = 0;
		if(!(res = GetCurrentDirectory(1024, parent_dir))){
			if(res > 1024){
				fprintf(stderr,"bigger buffer for directory path is needed.\n");
			}
			return -1;
		}
	}

	int slash_pos = 0;
	if(has_slash(file_name,&slash_pos)){
		char p[slash_pos+1];
		memset(p,0,slash_pos+1);
		strncpy(p,file_name,slash_pos);

		mbstate_t ps;
		wchar_t wstr[slash_pos+1];
		wmemset(wstr,0,slash_pos+1);

		char *pp = &p[0];
		if(mbsrtowcs(wstr,(const char ** restrict)&pp,slash_pos+1,&ps) == -1) return -1;

		if(!CreateDirectoryW(wstr,NULL)){
			DWORD err = GetLastError();
			if(err != ERROR_ALREADY_EXISTS) return -1;
		}

		if(!SetCurrentDirectory(wstr)) return -1;

		char *s = file_name;
		if(create_folder(s + slash_pos +1) == -1) return -1;
	}

	if(!SetCurrentDirectory(parent_dir)) return -1;

#endif
	return 0;
}

long long read_file(char *file_name, uint8_t **file_content)
{
	FILE *fp = fopen(file_name,"rb");
	if(!fp) return -1;

	if(fseek(fp,0,SEEK_END) == -1){
		fclose(fp);
		return -1;
	}

	long long size = 0;
	if((size = ftell(fp)) == -1){
		fclose(fp);
		return -1;
	}

	rewind(fp);
		
	*file_content = malloc(size);
	if(!(*file_content)){
		fclose(fp);
		return -1;
	}
	
	memset(*file_content,0,size);
	if((long long)fread(*file_content,1,size,fp) != size){
		fclose(fp);
		free(*file_content);
		return -1;
	}

	fclose(fp);
	return size;
}

int write_file(char *compressed_file_name,uint8_t *data, uint64_t size)
{

	if(!is_path_legal(compressed_file_name)) return -1;
	if(!path_exist(compressed_file_name)){
		if(create_folder(compressed_file_name) == -1) return -1;
	}
	FILE *fp = fopen(compressed_file_name,"wb");
	if(!fp) return -1;

	if(fwrite(data,1,size,fp) != size) {
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

static int is_path_legal(const char *p)
{
	char *l = (char*)p;
	if(l[1] == '.') return 0;
	if(l[0] == '/') return 0;
	if(l[1] == ':') return 0;

	return 1;
}

static int path_exist(const char *p)
{
#if defined(__linux__) || defined(__APPLE__)
	errno = 0;	
	struct stat st;
	if(stat(p,&st) == -1){
		if(errno == ENOENT) return 0;
	}
#elif defined(_WIN32) || defined(_WIN64)
	char *s = (char *)p;

	mbstate_t ps;
	size_t l = strlen(s);
	wchar_t wstr[l+1];
	wmemset(wstr,0,l+1);

    if(mbsrtowcs(wstr,(const char ** restrict)&s,l,&ps) == -1) return -1;

	DWORD attr = GetFileAttributesW(wstr);
	if(attr == INVALID_FILE_ATTRIBUTES){
		DWORD err = GetLastError();
		if(err == ERROR_PATH_NOT_FOUND) return 0;
		if(err == ERROR_FILE_NOT_FOUND) return 1;
		return 0;
	}
#endif

	return 1;
}

static int has_slash(const char *p,int *pos)
{
	char *s = (char*)p;
	for(; *s && *s != '/'; s++);
	*pos = (int)(s - p);
	return *s == '/';
}
