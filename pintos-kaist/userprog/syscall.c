#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
// Project 2 : System Call
#include "kernel/stdio.h"
#include "threads/init.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "filesys/file.h"


void syscall_entry(void);
void syscall_handler(struct intr_frame *);

static struct lock filesys_lock;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
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
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	}
}

int write(int fd, const void *buffer, unsigned size)
{
	int bytes_written;
	struct thread *t = thread_current(); // 현재 쓰레드 포인터 획득
	check_user_ptr(buffer); // 버퍼 유효성 검사.

	if (fd == 1) // 출력 처리
	{
		putbuf(buffer, size);
		bytes_written = size;
	}
	else if(fd >= 2 && fd < MAX_FD && t->fd_table[fd] != NULL)
	{
		struct file *file = t->fd_table[fd];
		lock_acquire(&filesys_lock); //전역 락 획득.
		bytes_written = file_write(file, buffer, size); // 쓰기 연산.
		lock_release(&filesys_lock); // 전역 락 해제
	}
	else {
		return -1;
	}
	return bytes_written;
}

void halt()
{
	power_off();
}

void exit(int status)
{
	thread_current()->status_code = status;
	thread_exit(); // this leads to process exit.
}

int open(const char *file_name)
{ 

	struct thread *t = thread_current(); // 현재 쓰레드 포인터를 획득
	check_user_ptr(file_name); // 포인터 유효성 검사

	lock_acquire(&filesys_lock); // 전역 락 획득
	struct file *file = filesys_open(file_name); // 파일 오픈 작업 수행
	lock_release(&filesys_lock); // 전역 락 해제

	if (file == NULL) // 실패 시 -1 리턴.
	{
		return -1;
	}

	// File load success.
	int fd = t->next_fd; // fd 값 획득
	t->fd_table[fd] = file;  // 파일 테이블에 할당.
	t->next_fd++;

	return fd;
}

int create(const char *file, unsigned initial_size)
{
	check_user_ptr(file);
	return filesys_create(file, initial_size);
}

int read(int fd, void *buffer, unsigned size)
{
	int bytes_read;
	struct thread *t = thread_current();

	if (buffer == NULL || !is_user_vaddr(buffer) || pml4_get_page(t->pml4, buffer) == NULL)
	{
		exit(-1);
	}

	if (fd == 0)
	{
		input_init();
		uint8_t key = input_getc();
		return 1;
	}
	if (fd == 1)
	{
		return 0;
	}
	else
	{
		lock_acquire(&filesys_lock);
		bytes_read = file_write(t->fd_table[fd], buffer, size);
		lock_release(&filesys_lock);
		return bytes_read;
	}
}

void check_user_ptr(const char *buffer)
{
	struct thread *t = thread_current();
	if (buffer == NULL || !is_user_vaddr(buffer) || pml4_get_page(t->pml4, buffer) == NULL)
	{
		exit(-1);
	}
}