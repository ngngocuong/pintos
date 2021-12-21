#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define USER_VADDR_BOTTOM ((void *) 0x08048000)

static void syscall_handler (struct intr_frame *);
int user_to_kernel_ptr(const void *vaddr);
void get_arg (struct intr_frame *f, int *arg, int n);
void check_valid_ptr (const void *vaddr);
void check_valid_buffer (void* buffer, unsigned size);
void check_valid_string (const void* str);

void
syscall_init (void) 
{
  lock_init(&write_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //make an arguments list
  int arg[3];
  //check that the stack pointer is in user memory
  int esp = user_to_kernel_ptr((const void*) f->esp);
  switch (* (int *) esp)
  {
    case SYS_HALT:
    {
	halt(); 
	break;
    }
    case SYS_EXIT:
    {
       //get the id of the exiting process
	get_arg(f, &arg[0], 1);
	exit(arg[0]);
	break;
    }
    case SYS_EXEC:
    {
       //get the id of the executing process
	get_arg(f, &arg[0], 1);
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = exec((const char *) arg[0]); 
	break;
    }
    case SYS_WAIT:
    {
       //get the id of the waiting process
	get_arg(f, &arg[0], 1);
	f->eax = wait(arg[0]);
	break;
    }
    case SYS_CREATE:
    {
        //get the id and name of the created process file
	get_arg(f, &arg[0], 2);
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = create((const char *)arg[0], (unsigned) arg[1]);
	break;
    }
    case SYS_REMOVE:
    {
        //get the id of the remove process file
	get_arg(f, &arg[0], 1);
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = remove((const char *) arg[0]);
	break;
    }
    case SYS_OPEN:
    {
        //get the id of the opening process file
	get_arg(f, &arg[0], 1);
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = open((const char *) arg[0]);
	break; 		
    }
    case SYS_FILESIZE:
    {
        //get the file size of this process
	get_arg(f, &arg[0], 1);
	f->eax = filesize(arg[0]);
	break;
    }
    case SYS_READ:
    {
        //get the id, file_name, and file size
	get_arg(f, &arg[0], 3);
	check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
	arg[1] = user_to_kernel_ptr((const void *) arg[1]);
	f->eax = read(arg[0], (void *) arg[1], (unsigned) arg[2]);
	break;
    }
    case SYS_WRITE:
    { 
        //get the id, file_name, and file size
	get_arg(f, &arg[0], 3);
	check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
	arg[1] = user_to_kernel_ptr((const void *) arg[1]);
	f->eax = write(arg[0], (const void *) arg[1],
		       (unsigned) arg[2]);
	break;
    }
    case SYS_SEEK:
    {
        //get the id and file_name
	get_arg(f, &arg[0], 2);
	seek(arg[0], (unsigned) arg[1]);
	break;
    } 
    case SYS_TELL:
    { 
        //get the id
	get_arg(f, &arg[0], 1);
	f->eax = tell(arg[0]);
	break;
    }
    case SYS_CLOSE:
    { 
        //get the id
	get_arg(f, &arg[0], 1);
	close(arg[0]);
	break;
    }
  }
}

void halt (void)
{
  shutdown_power_off();
}

void exit (int status)
{
  struct thread *cur = thread_current();
  if (thread_running(cur->parent) && cur->p)
    cur->p->status = status;
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

pid_t exec (const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  struct child* p = get_child_process(pid);
  if (p == NULL)
    return -1;
  if (p->load == 0)
     sema_down(&p->load_sema);
  if (p->load == 2)
  {
    remove_child_process(p);
    return -1;
  }
  return pid;
}

int wait (pid_t pid)
{
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size)
{
  lock_acquire(&write_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&write_lock);
  return success;
}

bool remove (const char *file)
{
  lock_acquire(&write_lock);
  bool success = filesys_remove(file);
  lock_release(&write_lock);
  return success;
}

int open (const char *file)
{
  lock_acquire(&write_lock);
  struct file *f = filesys_open(file);
  if (f == NULL)
  {
      lock_release(&write_lock);
      return -1;
  }
  int fd = open_file(f);
  lock_release(&write_lock);
  return fd;
}

int filesize (int fd)
{
  lock_acquire(&write_lock);
  struct file *f = find_file(fd);
  if (f == NULL)
  {
      lock_release(&write_lock);
      return -1;
  }
  int size = file_length(f);
  lock_release(&write_lock);
  return size;
}

int read (int fd, void *buffer, unsigned size)
{
  if (fd == STDIN_FILENO)
  {
      unsigned i = 0;
      uint8_t* b = (uint8_t *)buffer;
      for (; i < size; i++)
        b[i] = input_getc();
      return size;
  }
  lock_acquire(&write_lock);
  struct file *f = find_file(fd);
  if (f == NULL)
  {
      lock_release(&write_lock);
      return -1;
  }
  int bytes = file_read(f, buffer, size);
  lock_release(&write_lock);
  return bytes;
}

int write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
  {
      putbuf(buffer, size);
      return size;
  }
  int bytes = 0;
  lock_acquire (&write_lock);
  struct file *f = find_file(fd);
  if (f == NULL)
    bytes = -1;
  else
    bytes = file_write(f, buffer, size);
  lock_release(&write_lock);
  return bytes;
}

void seek (int fd, unsigned position)
{
  lock_acquire (&write_lock);
  struct file *f = find_file (fd);
  if (f != NULL)
    file_seek (f, position);
  lock_release (&write_lock);
}

unsigned tell (int fd)
{
  unsigned i = 0;
  lock_acquire (&write_lock);
  struct file *f = find_file (fd);
  if (f == NULL)
    i = -1;
  else
    i = (unsigned)file_tell (f);
  lock_release (&write_lock);
  return i;
}

void close (int fd)
{
  lock_acquire (&write_lock);
  close_file (fd);
  lock_release (&write_lock);
}

void check_valid_ptr (const void *vaddr)
{
  if (!is_user_vaddr(vaddr) || vaddr < (void*)0x08048000)
    exit (-1);
}

int user_to_kernel_ptr(const void *vaddr)
{
  check_valid_ptr (vaddr);
  void *ptr = pagedir_get_page (thread_current()->pagedir, vaddr);
  if (ptr == NULL)
    exit(-1);
  return (int)ptr;
}
