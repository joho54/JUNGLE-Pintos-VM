#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
int write(int fd, void *buffer, unsigned size);
void halt(void);
void exit (int status);
int create(const char *file, unsigned initial_size);

#endif /* userprog/syscall.h */
