#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

int child_done;
static struct lock lock;
static struct condition condition;

void thread_join(struct thread *);
void init_kernel_monitor(void);
// int process_exec_pass1(const char *cmd_line);

#endif /* userprog/process.h */
