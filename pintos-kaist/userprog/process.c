#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);

struct fork_data{
	struct thread *parent;
	struct intr_frame *if_;
};

/* General process initializer for initd and other process. */
static void
process_init(void)
{
	struct thread *current = thread_current();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name)
{
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy(fn_copy, file_name, PGSIZE);

	/* Create a new thread to execute FILE_NAME. */
	char temp_name[16];
    strlcpy(temp_name, file_name, sizeof temp_name);
    
    char *save_ptr;
    char *prog_name = strtok_r(temp_name, " \t", &save_ptr);
    
	tid = thread_create(prog_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page(fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd(void *f_name)
{
#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
#endif

	process_init();

	if (process_exec(f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED)
{
	struct fork_data fork_data;
	fork_data.parent = thread_current();
	fork_data.if_ = if_;
	
	tid_t child_tid = thread_create(name,
						 PRI_DEFAULT, __do_fork, &fork_data);
	if (child_tid == TID_ERROR) return TID_ERROR;
	
	/* Clone current thread to new thread.*/
	struct thread *child = thread_get_child(child_tid);
	if (child) sema_down(&child->fork_sema);
	else return TID_ERROR;

	return child_tid;
}

struct thread *thread_get_child(const tid_t child_tid)
{
	struct list_elem *e = list_begin(&thread_current()->childs);
	for (; e != list_end(&thread_current()->childs); e = list_next(e))
	{
		struct thread *child = list_entry(e, struct thread, child_elem);
		if (child->tid == child_tid)
		{
			return child;
		}
	}
	return NULL;

}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
// pml4_for_each 함수가 포인터로 사용함. 결과적으로 각 페이지 테이블에서 PTE를 순회하며 적용됨.
duplicate_pte(uint64_t *pte, void *va, void *aux)
{
	struct thread *current = thread_current();
	struct thread *parent = (struct thread *)aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	// 해당 PTE에 대응하는 가상주소가 커널 가상 주소인지 확인.
	if (is_kernel_vaddr(va))
	{
		return true; // true를 리턴하라는 의미였구나. 이유가 뭐지? 
	}
	/* 2. Find physical page corresponding to VA from parent's PML4. */
	parent_page = pml4_get_page(parent->pml4, va);
	if(parent_page == NULL) {
		return false;
	}

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO); // 새로운 페이지를 유저 영역에 생성.
	if(newpage == NULL) {
		return false;
	}
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE); // 페이지 복사.
	
	// 이 pte는 누구 거야? pml4_for_each()에서 부모의 pml4를 호출했으니, 부모의 모든 페이지에서 pte의 writable을 조회하는 결과임.
	writable = is_writable(pte); 
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	//   pml4_set_page (uint64_t *pml4, void *upage, void *kpage, bool rw) {
	if (!pml4_set_page(current->pml4, va, newpage, writable)) 
	{
		/* 6. TODO: if fail to insert page, do error handling. */
		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork(void *aux)
{
	struct intr_frame if_;
	struct fork_data *fork_data = (struct fork_data *)aux;
	struct thread *parent = fork_data->parent;
	struct thread *current = thread_current();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = fork_data->if_;
	bool succ = true;


	// printf("current thread id: %d\n", current->tid);

	/* 1. Read the cpu context to local stack. */
	memcpy(&if_, parent_if, sizeof(struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	// printf("above process activate\n");
	process_activate(current);
#ifdef VM
	supplemental_page_table_init(&current->spt);
	if (!supplemental_page_table_copy(&current->spt, &parent->spt))
		goto error;
#else
	// printf("copying page table\n");
	if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
		goto error;
#endif
	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	// printf("copying file descriptor table\n");
	 for (int fd = 2; fd < MAX_FD; fd++) { // 이쪽은 fdt 리팩터링 후 다시 구현 필요. 현재는 문제 없어 보임.
        if (parent->fdt[fd] != NULL) {
			// printf("duplicating fdt[%d]\n", fd);
            current->fdt[fd] = file_duplicate(parent->fdt[fd]);
			// printf("parent file: %p -> child file: %p\n", parent->fdt[fd], current->fdt[fd]);
        }
    }
	// printf("fdt copy over\n"s);
	current->next_fd = parent->next_fd;
	// printf("%d = %d\n", current->next_fd, parent->next_fd);
	// printf("####fdt copy complete. %s's current fdt\n", thread_current()->name);
	// for (int fd = 0; fd < MAX_FD; fd++)
	// {
	// 	if(current->fdt[fd])
	// 		printf("fdt[%d] = %p\n", fd, current->fdt[fd]);
	// }
	// copying running_file
	// printf("duplicating running fiel\n");
	char *file_name = parent->name;
	current->running_file = NULL;
	// file_deny_write(current->running_file);

	// printf("open complete\n");
	
	process_init();

	/* Finally, switch to the newly created process. */
	// printf("switching to child. unblocking\n");
	if_.R.rax = 0; // 여기서 자식 프로세스로는 리턴 값이 0으로 넘어감.

	if (succ){
		sema_up(&thread_current()->fork_sema);
		do_iret(&if_);
	}
error:
	// printf("error: directly going to exit\n");
	thread_exit();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name) {
	char *file_name = f_name;
	bool success;
	// printf("my name is %s\n", thread_current()->name);
	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup();

	/* And then load the binary */
	success = load(file_name, &_if);
	
	// printf("success: %d\n", success);
	/* If load failed, quit. */
	palloc_free_page(file_name);
	// printf("freed palloc page\n");
	if (!success){
		// printf("exec failed. returning\n");
		return -1;
	}
	/* Start switched process. */

	// printf("####exec almost complete. %s's current fdt\n", thread_current()->name);
	// for (int fd = 0; fd < MAX_FD; fd++)
	// {
	// 	if(thread_current()->fdt[fd])
	// 		printf("fdt[%d] = %p\n", fd, thread_current()->fdt[fd]);
	// }
	do_iret(&_if);
	
	NOT_REACHED();
}

// int process_exec_pass1(const char *cmd_line)
// {
// 	char *fn_copy;
// 	tid_t tid;

// 	/* Make a copy of cmdline.
// 	 * Otherwise there's a race between the caller and load(). */
// 	fn_copy = palloc_get_page(0);

// 	if (fn_copy == NULL)
// 		return TID_ERROR;

// 	strlcpy(fn_copy, cmd_line, PGSIZE);
	
// 	tid = thread_create(cmd_line, PRI_DEFAULT, process_exec, fn_copy);

// 	// printf("%s waits for the %s\n",thread_current()->name, thread_get_child(tid)->name);
// 	struct thread *child = thread_get_child(tid);
// 	sema_down(&child->exec_sema);
// 	if (child->exec_success) {
// 		thread_exit();
// 		NOT_REACHED();
// 	}
// 	// failed
// 	return -1;
// }

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait(tid_t child_tid)
{
	struct thread *child = NULL;

	if (child_tid == 0) {
		struct list_elem *e = list_begin(&thread_current()->childs);
		if (e != list_end(&thread_current()->childs)) {
			child = list_entry(e, struct thread, child_elem);
		}
	} else {
		child = thread_get_child(child_tid);
	}
	
	if (child) {

		sema_down(&child->wait_sema);
		list_remove(&child->child_elem);  // 대기가 완료된 리스트는 삭제해야 후환이 없습니다.
		int status_code = child->status_code;
		sema_up(&child->exit_sema);
		return status_code; // 종료 코드는 여기에서 리턴됩니다.
	}
	// child를 찾을 수 없는 경우.
	return -1;
}

void thread_join(struct thread *child)
{
	lock_acquire(&child->lock);
	while (child->done == 0)
	{
		cond_wait(&child->condition, &child->lock);
	}
	lock_release(&child->lock);
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void)
{
	struct thread *current = thread_current();
	// printf("process exit called. running file: %p\n", curr->running_file);

	if(current->fdt) {
		for (int fd = 0; fd < MAX_FD; fd++)
		{
			if(current->fdt[fd])
			{ 
				file_close(current->fdt[fd]);
			}
		}
		palloc_free_page(current->fdt);
	}

	if (current->running_file){
		file_close(current->running_file);
	}
	process_cleanup(); 
	sema_up(&current->wait_sema);
	sema_down(&current->exit_sema);
}

// get minimal fd value of thread t
int get_next_fd(struct thread *t)
{
	for (int fd = 2; fd < MAX_FD; fd++)
	{
		/* code */
		if(t->fdt[fd] == NULL){
			return fd;
		}
	}
	return -1;
	
}

/* Free the current process's resources. */
static void
process_cleanup(void)
{
	struct thread *curr = thread_current();

#ifdef VM
	supplemental_page_table_kill(&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL)
	{
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate(NULL);
		pml4_destroy(pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next)
{
	/* Activate thread's page tables. */
	pml4_activate(next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0			/* Ignore. */
#define PT_LOAD 1			/* Loadable segment. */
#define PT_DYNAMIC 2		/* Dynamic linking info. */
#define PT_INTERP 3			/* Name of dynamic loader. */
#define PT_NOTE 4			/* Auxiliary info. */
#define PT_SHLIB 5			/* Reserved. */
#define PT_PHDR 6			/* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr
{
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR
{
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes,
						 bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load(const char *file_name, struct intr_frame *if_)
{
	struct thread *t = thread_current();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	char *token;
	int argc = 0;
	char *argv[32];
	char *argv_address[32];
	char *save_ptr;
	void *initial_rsp;

	token = strtok_r(file_name, " ", &save_ptr);
	while (token != NULL)
	{
		argv[argc++] = token;
		token = strtok_r(NULL, " ", &save_ptr);
	}
	file_name = argv[0];

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create();
	if (t->pml4 == NULL)
		goto done;
	process_activate(thread_current());

	/* Open executable file. */

	file = filesys_open(file_name);


	if (file == NULL)
	{
		printf("load: %s: open failed\n", file_name);
		goto done;
	}
	// printf("%s is opneing %p as a running file\n", t->name, file);
	t->running_file = file;
	file_deny_write(t->running_file);
	// printf("## denied!\n");

	/* Read and verify executable header. */
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E // amd64
		|| ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
	{
		printf("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* Ignore this segment. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint64_t file_page = phdr.p_offset & ~PGMASK;
				uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint64_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
					 * Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
				}
				else
				{
					/* Entirely zero.
					 * Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment(file, file_page, (void *)mem_page,
								  read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack(if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;
	initial_rsp = if_->rsp;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */
	for (i = argc - 1; i >= 0; i--)
	{ // 주석은 첫 실행 후 주소 변화 정상 작동에 대해서.
		size_t len = strlen(argv[i]) + 1;
		if_->rsp -= len;
		memcpy(if_->rsp, argv[i], len);
		argv_address[i] = if_->rsp;
	}

	while (if_->rsp % 8 != 0)
	{
		if_->rsp--;
		*(uint8_t *)if_->rsp = 0;
	}

	for (i = argc; i >= 0; i--)
	{
		if_->rsp -= sizeof(char *);
		if (i == argc)
		{
			memset(if_->rsp, 0, 8);
		}
		else
		{
			memcpy(if_->rsp, &argv_address[i], 8);
		}
	}

	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp;

	if_->rsp -= 8;
	memset(if_->rsp, 0, 8);
	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Phdr *phdr, struct file *file)
{
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t)file_length(file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr((void *)phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
		{
			palloc_free_page(kpage);
			return false;
		}
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page(upage, kpage, writable))
		{
			printf("fail\n");
			palloc_free_page(kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack(struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kpage != NULL)
	{
		success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page(kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment(struct page *page, void *aux)
{
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer(VM_ANON, upage,
											writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack(struct intr_frame *if_)
{
	bool success = false;
	void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
