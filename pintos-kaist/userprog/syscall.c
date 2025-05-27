// #include "userprog/syscall.h" <- 유저 프로그램 쪽 syscall.h를 잘못 불러와서 헤더 불일치를 야기함.
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
#include "threads/palloc.h"
#include "lib/string.h"

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
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	case SYS_SEEK:
		file_seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = file_tell(f->R.rdi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		// printf("fork complete. returned tid: %d\n", f->R.rax);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_EXEC:
		exec(f->R.rdi); 
		break;
	}
}

int write(int fd, const void *buffer, unsigned size)
{
	int bytes_written;
	struct thread *t = thread_current(); // 현재 쓰레드 포인터 획득
	check_user_ptr(buffer);				 // 버퍼 유효성 검사.

	if (fd == 1) // 출력 처리
	{
		putbuf(buffer, size);
		bytes_written = size;
	}
	else if (fd >= 2 && fd < MAX_FD && t->fd_table[fd] != NULL)
	{
		struct file *file = t->fd_table[fd];
		lock_acquire(&filesys_lock);					// 전역 락 획득.
		bytes_written = file_write(file, buffer, size); // 쓰기 연산.
		lock_release(&filesys_lock);					// 전역 락 해제
	}
	else
	{
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
	check_user_ptr(file_name);			 // 포인터 유효성 검사
	// printf("%s is trying to open %s\n", t->name, file_name);
	lock_acquire(&filesys_lock);				 // 전역 락 획득
	struct file *file = filesys_open(file_name); // 파일 오픈 작업 수행
	lock_release(&filesys_lock);				 // 전역 락 해제

	if (file == NULL) // 실패 시 -1 리턴.
	{
		// printf("filesys open failed\n");
		return -1;
	}

	// File load success.
	// printf("filesys open complete\n");
	// 해당 프로세스의 파일 디스크립터 숫자 중에 사용하지 않는 가장 작은 값을 할당해 줍니다.
	int fd = t->next_fd;	// fd 값 획득
	t->fd_table[fd] = file; // 파일 테이블에 할당.
	// printf("file allocated to fdt: t->fd_table[fd] = %p\n", t->fd_table[fd]);
	t->next_fd++;
	// printf("%s opened %s with the fd of %d\n", t->name, file_name, fd);
	return fd;
}

int create(const char *file, unsigned initial_size)
{
	check_user_ptr(file);
	lock_acquire(&filesys_lock);				 // 전역 락 획득
	int result = filesys_create(file, initial_size);
	lock_release(&filesys_lock);				 // 전역 락 해제
	return result;
}

int remove(const char *file)
{
	check_user_ptr(file);
	lock_acquire(&filesys_lock);				 // 전역 락 획득
	int result = filesys_remove(file);
	lock_release(&filesys_lock);				 // 전역 락 해제
	return result;
}

// returns number of bytes actually read
int read(int fd, void *buffer, unsigned size)
{
	int bytes_read;
	struct thread *t = thread_current();

	check_user_ptr(buffer);

	if (fd == 0)
	{
		input_init();
		uint8_t key = input_getc();
		return 1;
	}
	else if (fd >= 2 && fd < MAX_FD && t->fd_table[fd] != NULL)
	{
		struct file *file = t->fd_table[fd];

		lock_acquire(&filesys_lock);
		bytes_read = file_read(file, buffer, size);
		lock_release(&filesys_lock);
		return bytes_read;
	}
	else
	{
		return -1;
	}
}

void check_user_ptr(const char *buffer)
{
	if (buffer == NULL || !is_user_vaddr(buffer) || pml4_get_page(thread_current()->pml4, buffer) == NULL)
	{
		exit(-1);
	}
}

int filesize(int fd)
{
	struct thread *t = thread_current();
	if (fd >= 2 && fd < MAX_FD && t->fd_table[fd] != NULL)
	{
		struct file *file = t->fd_table[fd];
		lock_acquire(&filesys_lock);
		int file_size = file_length(file);
		lock_release(&filesys_lock);
		return file_size;
	}
	return -1;
}

void close(int fd)
{

	struct thread *t = thread_current();

	if (fd >= 2 && fd < MAX_FD && t->fd_table[fd] != NULL)
	{
		struct file *file = t->fd_table[fd];

		lock_acquire(&filesys_lock);
		file_close(file);
		lock_release(&filesys_lock);
		t->fd_table[fd] = NULL;
	}
}

unsigned tell(int fd)
{
	struct thread *t = thread_current();
	if (fd >= 2 && fd < MAX_FD && t->fd_table[fd] != NULL)
	{
		struct file *file = t->fd_table[fd];
		lock_acquire(&filesys_lock);
		unsigned off = file_tell(file);
		lock_release(&filesys_lock);
		return off;
	}
	return NULL;
}

void seek(int fd, unsigned position)
{
	struct thread *t = thread_current();
	if (fd >= 2 && fd < MAX_FD && t->fd_table[fd] != NULL)
	{
		struct file *file = t->fd_table[fd];
		lock_acquire(&filesys_lock);
		file_seek(file, position);
		lock_release(&filesys_lock);
	}
}

int fork (const char *thread_name, struct intr_frame *f) {
	return process_fork(thread_name, f);
}

int wait (int pid) {
	int status_code = process_wait(pid);
	return status_code;
}

void exec (const char *cmd_line)
{
	check_user_ptr(cmd_line);
	// cmd_line을 새로운 영역에 할당(왜 해줘야 하는지 모르겠음) 프로세스가 데이터가 덮어 씌워져서 그렇다고는 하는데
	// 쓰레드 자체는 커널 공간에 있어서 그렇다. 아래 copy를 위한 할당 영역도 커널 공간에 돼 있다.
	void *copy = palloc_get_page(PAL_ZERO);
	if (copy == NULL) return -1;
	memcpy(copy, cmd_line, strlen(cmd_line)+1);
	if (process_exec(copy) == -1) {
		// printf("exec failed\n");
		exit(-1);
	}
}


