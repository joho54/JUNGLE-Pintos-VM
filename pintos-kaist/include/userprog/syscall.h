#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
int write(int fd, const void *buffer, unsigned size);
void halt(void);
void exit (int status);
int create(const char *file, unsigned initial_size);
int read (int fd, void *buffer, unsigned size);
void check_user_ptr(const char *buffer);
int filesize(int fd);
void close(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
int remove(const char *file);
int fork_ (const char *thread_name, struct intr_frame *f);
int wait (int pid);
#endif /* userprog/syscall.h */
