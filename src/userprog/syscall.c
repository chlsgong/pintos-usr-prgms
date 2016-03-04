#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "devices/shutdown.h"

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
int valid_pointer(void *pointer);

void syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
  const void *write_buffer;
  unsigned position;
  int syscall = *(int *)(f->esp);
  f->esp += sizeof(int);
  switch(syscall) {
  	case(SYS_HALT):
  		halt();
  		break;
  	case(SYS_EXIT):
  		/*Read from stack once*/
  		status = *(int *)(f->esp);
  		exit(status);
  		break;
  	case(SYS_EXEC):
  		/*Read from stack to get file pointer, check if valid*/
  		file = f->esp;
  		exec(file);
  		break;
  	case(SYS_WAIT):
  		/*Read from stack once*/
  		pid = *(int *)(f->esp);
  		wait(pid);
  		break;
  	case(SYS_CREATE):
  		/*Read from stack twice, check if file is valid*/
  		file = f->esp;
  		f->esp += sizeof(int);
  		initial_size = *(unsigned *)(f->esp);
  		create(file, initial_size);
  		break;
  	case(SYS_REMOVE):
  		/*Read from stack once, check if file is valid*/
  		file = f->esp;
  		remove(file);
  		break;
  	case(SYS_OPEN):
  		/*Read from stack once, check if file is valid*/
  		file = f->esp;
  		open(file);
  		break;
  	case(SYS_FILESIZE):
  		/*Read from stack once*/
  		fd = *(int *)(f->esp);
  		filesize(fd);
  		break;
  	case(SYS_READ):
  		/*Read from stack 3 times, check if buffer is valid*/
  		fd = *(int *)(f->esp);
  		f->esp += sizeof(int);
  		read_buffer = f->esp;
  		f->esp += sizeof(int);
  		size = *(unsigned *)(f->esp);
  		read(fd, read_buffer, size);
  		break;
  	case(SYS_WRITE):
  		/*Read from stack 3 times, check if buffer is valid*/
  		fd = *(int *)(f->esp);
  		f->esp += sizeof(int);
  		write_buffer = f->esp; /////////////////??
  		f->esp += sizeof(int);
  		size = *(unsigned *)(f->esp);
  		write(fd, write_buffer, size);
  		break;
  	case(SYS_SEEK):
  		/*Read from stack twice*/
  		fd = *(int *)(f->esp);
  		f->esp += sizeof(int);
  		position = *(unsigned *)(f->esp);
  		seek(fd, position);
  		break;
  	case(SYS_TELL):
  		/*Read from stack once*/
  		fd = *(int *)(f->esp);
  		tell(fd);
  		break;
  	case(SYS_CLOSE):
  		/*Read from stack once*/
  		fd = *(int *)(f->esp);
  		close(fd);
  		break;
  	default:
  		printf ("system call! %d \n", syscall);
  		thread_exit ();
  }
}


int valid_pointer(void *pointer) {
	struct thread *cur_thread = thread_current();
	if(pointer == NULL || is_kernel_vaddr(pointer) ||
	  pagedir_get_page (cur_thread->pagedir, pointer) == NULL) {
		thread_exit();
		return 0;
	}
	return 1;
}


void halt () {
	shutdown_power_off();
}

void exit (int status UNUSED) {
	/*Come back to this later and finish it*/
	thread_exit();
}

pid_t exec (const char *file) {
	return -1;
}

pid_t wait (pid_t pid) {
	return -1;
}

bool create (const char *file, unsigned initial_size){
	return 0;
}

bool remove (const char *file){
	return 0;
}

int open (const char *file){
	return -1;
}

int filesize (int fd){
	return -1;
}

int read (int fd, void *buffer, unsigned size){
	return -1;
}

int write (int fd, const void *buffer, unsigned size) {
	char s[size];
	snprintf(s, size, "%s", buffer);
	puts(s);
	return size;
}

void seek (int fd, unsigned position){}

unsigned tell (int fd){
	return 0;
}

void close (int fd){}


