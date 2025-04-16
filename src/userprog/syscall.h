#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/stdbool.h"
void syscall_init(void);

bool sys_create(const char* file_name, unsigned initial_size);
bool sys_remove(const char* file_name);
int sys_open(const char* file_name);
void sys_close(int fd);
int sys_filesize(int fd);
int sys_read(int fd, void* buffer, unsigned size);
int sys_write(int fd, const void* buffer, unsigned size);
unsigned sys_tell(int fd);
void sys_seek(int fd, unsigned position);

#endif /* userprog/syscall.h */
