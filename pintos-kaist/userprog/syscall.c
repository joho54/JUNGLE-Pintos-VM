#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/kernel/stdio.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf("rax: %ld, rdi: %ld, rsi: %ld, rdx: %ld, r10: %ld, r8: %ld, r9: %ld\n", f->R.rax, f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8, f->R.r9);
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	}

	do_iret(f);
}

int
write(int fd, void *buffer, unsigned size){ 
	// printf("write called! %d\n", fd);
	int bytes_written;
	struct thread *t = thread_current();
	
	if (fd == 1) {
		putbuf(buffer, size);
		bytes_written = size;
	}
	else {
		printf("fd_table[%d] %p\n ", fd, t->fd_table[fd-3]);
		bytes_written = file_write(t->fd_table[fd-3], buffer, size);
		bytes_written = 0;
		return bytes_written;
	}
	
}

void
halt(){
	power_off();
}

void 
exit (int status) {
	thread_current()->status_code = status;
	thread_exit(); // this leads to process exit.
}

int
open(const char *file_name){

	struct thread *t = thread_current();

	if(!file_name){
		return -1;
	}

	struct file *file = filesys_open(file_name);

	if(!file){ // file open failed
		return -1;
	}

	// File load success.
	t->fd_cnt++;
	t->fd_table[t->fd_cnt - 3] = file; 
	return t->fd_cnt;
}

int
create(const char *file, unsigned initial_size)
{
	if (!file){
		exit(-1);
		return -1;
	}
	return filesys_create(file, initial_size);
}


