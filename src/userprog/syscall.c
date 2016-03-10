#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "kernel/console.h"
#include "threads/palloc.h"

static void syscall_handler (struct intr_frame *);

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int valid_pointer(const void *pointer);

// Lock variable
struct lock file_lock;

void syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int status;
  const char *file;
  pid_t pid;
  unsigned initial_size;
  int fd;
  void *read_buffer;
  unsigned size;
  const char *write_buffer;
  unsigned position;
  int syscall;

  valid_pointer(f->esp);
  syscall = *(int *)(f->esp);

  switch(syscall) {
  	case(SYS_HALT):
  		halt();
  		break;
  	case(SYS_EXIT):
  		/*Read from stack once*/
      valid_pointer(f->esp + 4);
  		status = *(int *)(f->esp + 4);
  		exit(status);
  		break;
  	case(SYS_EXEC):
  		/*Read from stack to get file pointer, check if valid*/
      valid_pointer(f->esp + 4);
  		file = *(char **)(f->esp + 4);
  		f->eax = exec(file);
  		break;
  	case(SYS_WAIT):
  		/*Read from stack once*/
  		pid = *(int *)(f->esp + 4);
  		f->eax = wait(pid);
  		break;
  	case(SYS_CREATE):
      // printf("\nAYYYYYYYYEEEEE: CREATE\n");
  		/*Read from stack twice, check if file is valid*/
  		file = f->esp + 4;
  		initial_size = *(unsigned *)(f->esp + 8);
  		create(file, initial_size);
  		break;
  	case(SYS_REMOVE):
      // printf("\nAYYYYYYYYEEEEE: REMOVE\n");
  		/*Read from stack once, check if file is valid*/
  		file = f->esp + 4;
  		remove(file);
  		break;
  	case(SYS_OPEN):
      // printf("\nAYYYYYYYYEEEEE: OPEN\n");
  		/*Read from stack once, check if file is valid*/
  		file = f->esp + 4;
  		open(file);
  		break;
  	case(SYS_FILESIZE):
      // printf("\nAYYYYYYYYEEEEE: FILESIZE\n");
  		/*Read from stack once*/
  		fd = *(int *)(f->esp + 4);
  		filesize(fd);
  		break;
  	case(SYS_READ):
  		/*Read from stack 3 times, check if buffer is valid*/
      // printf("\nAYYYYYYYYEEEEE: READ\n");
  		fd = *(int *)(f->esp + 4);
  		read_buffer = f->esp + 8;
  		size = *(unsigned *)(f->esp + 12);
  		read(fd, read_buffer, size);
  		break;
  	case(SYS_WRITE):
  		/*Read from stack 3 times, check if buffer is valid*/
  		fd = *(int *)(f->esp + 4);
  		write_buffer = *(char**)(f->esp + 8);
  		size = *(unsigned *)(f->esp + 12);
  		write(fd, write_buffer, size);
  		break;
  	case(SYS_SEEK):
  		/*Read from stack twice*/
      // printf("\nAYYYYYYYYEEEEE: SEEK\n");
  		fd = *(int *)(f->esp + 4);
  		position = *(unsigned *)(f->esp + 8);
  		seek(fd, position);
  		break;
  	case(SYS_TELL):
  		/*Read from stack once*/
      // printf("\nAYYYYYYYYEEEEE: TELL\n");
  		fd = *(int *)(f->esp + 4);
  		tell(fd);
  		break;
  	case(SYS_CLOSE):
      // printf("AYYYYYYYYEEEEE: CLOSE\n");
  		/*Read from stack once*/
  		fd = *(int *)(f->esp + 4);
  		close(fd);
  		break;
  	default:
  		printf ("system call! %d \n", syscall);
  		thread_exit ();
  }
}


int valid_pointer(const void *pointer) {
	struct thread *cur_thread = thread_current();
	if(pointer == NULL || is_kernel_vaddr(pointer) ||
	  pagedir_get_page (cur_thread->pagedir, pointer) == NULL) {
		exit(-1);
		return 0;
	}
	return 1;
}

void halt () {
	shutdown_power_off();
}

void exit (int status) {
  struct zombie* z = palloc_get_page(PAL_ZERO); // allocate
  struct list_elem* e;
  struct zombie* reaped;

  z->exit_status = status;
  z->tid = thread_current()->tid;
  list_push_back(&thread_current()->parent_process->zombies, &z->z_elem); // add to parent's zombie list
  list_remove(&thread_current()->child_elem); // remove from parent's children list

  // deallocate all its children
  // if(!list_empty(&thread_current()->zombies)) {
  //   for (e = list_begin (&thread_current()->zombies); 
  //      e != list_end (&thread_current()->zombies);
  //      e = list_next (e)) 
  //     {
  //       reaped = list_entry(e, struct zombie, z_elem);
  //       palloc_free_page(reaped);
  //     }
  // }

  printf("%s: exit(%d)\n", thread_current()->file_name, status);  
  sema_up(&thread_current()->process_sema);
  thread_exit();
}

pid_t exec (const char *file) {
  valid_pointer(file);
  process_execute(file);
  if(thread_current()->success) {
    return thread_current()->child_pid;
  }
  return PID_ERROR;
}

int wait (pid_t pid) {
	return process_wait((tid_t) pid);
}

bool create (const char *file, unsigned initial_size){
  if (valid_pointer(file)) {
    return filesys_create(file, initial_size);
  }
}

bool remove (const char *file){
  valid_pointer(file);
	return 0;
}

int open (const char *file){
  valid_pointer(file);
	return -1;
}

int filesize (int fd){
  // need to access file from thread_current() file table
  /*const char *file = thread_current() -> file_table[fd]
    int size = file_length(file);
	  return size; */
    return -1;
}

int read (int fd, void *buffer, unsigned size){
  valid_pointer(buffer);
	return -1;
}

int write (int fd, const void *buffer, unsigned size) {
  // may have to break up buffer if too long////////
  // lock_acquire(&file_lock);
  int num_bytes = -1;
  if (fd == 1) {
   valid_pointer(buffer);
   putbuf(buffer, (int) size);
   num_bytes = written_chars();
  }
  else{
    // file_write()
  }
  // lock_release(&file_lock);
	return num_bytes;
}

void seek (int fd, unsigned position){}

unsigned tell (int fd){
	return 0;
}

void close (int fd){
}


