#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "lib/kernel/console.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

static int get_user(const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte) UNUSED;

static void get_args (struct intr_frame *f, int *args, int num_args);
static void validate_buffer(const void *buffer, unsigned size);
static void validate_user_pointer(const void *ptr);
static void validate_string(const char *str);

/* System call functions */
static void sys_halt(void);
static void sys_exit(int status);
static pid_t sys_exec(const char *cmd_line);
static int sys_wait(pid_t pid);
static bool sys_create(const char *file, unsigned initial_size);
static int sys_write(int fd, const void *buffer, unsigned size);

static struct lock filesys_lock;

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_number;
  int args[3];
  if (!is_user_vaddr(f->esp))
    sys_exit(-1); // terminate if process is invalid
  
  syscall_number = *(int *)f->esp;

  switch (syscall_number)
  {
    case SYS_HALT:
      sys_halt();
      break;

    case SYS_EXIT:
      get_args(f, &args[0], 1);
      sys_exit(args[0]);
      break;
    
    case SYS_EXEC:
      get_args(f, &args[0], 1);
      validate_string((const char *)args[0]);
      f->eax = sys_exec((const char *)args[0]);
      break;

    case SYS_WAIT:
      get_args(f, &args[0], 1);
      f->eax = sys_wait(args[0]);
      break;

    case SYS_CREATE:
      get_args(f, &args[0], 2);
      validate_string((const char *)args[0]);
      f->eax = sys_create((const char *)args[0], (unsigned)args[1]);
      break;

    case SYS_WRITE:
      get_args(f, args, 3);
      validate_buffer((const void*)args[1], args[2]);
      f->eax = sys_write(args[0], (const void *)args[1], args[2]);
      break;

    // case 

    default:
      printf("Unknown system call: %d\n", syscall_number);
      sys_exit(-1);
      break;
  }

  thread_exit ();
}

static void 
get_args (struct intr_frame *f, int *args, int num_args)
{
  int *ptr;
  for (int i = 0; i < num_args; i++)
  {
    ptr = (int *)f->esp + i + 1; // +1 to skip syscall_number
    validate_user_pointer((const void *)ptr);
    args[i] = *ptr;
  }
}

static void
validate_buffer (const void *buffer, unsigned size)
{
  char *buf = (char *)buffer;
  for (unsigned i = 0; i < size; i++)
  {
    validate_user_pointer ((const void *)(buf + i));
  }
}

static void 
validate_user_pointer (const void *ptr) 
{
  if (ptr == NULL || !is_user_vaddr(ptr) || 
  pagedir_get_page(thread_current()->pagedir, ptr) == NULL) 
  {
    sys_exit (-1);
  }
} 

static void
validate_string(const char *str)
{
  while (true)
    {
      validate_user_pointer((const void *)str);
      if (*str == '\0')
      break;
      str++;
    }
}

static void
sys_halt (void)
{
  shutdown_power_off ();
}

static void
sys_exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}

static pid_t
sys_exec(const char *cmd_line)
{
  validate_string (cmd_line);
  return process_execute (cmd_line);
}

static int 
sys_wait (pid_t pid) 
{
  return process_wait (pid);
}

static bool
sys_create (const char *file, unsigned initial_size)
{
  bool success;

  lock_acquire(&filesys_lock);
  success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);

  return success;
}

static int
sys_write (int fd, const void *buffer, unsigned size)
{
  int bytes_written;

  validate_buffer (buffer, size);

  if (fd == STDOUT_FILENO) // case for writing to console when fd 1
  {
    putbuf (buffer, size);
    return size;
  } 
  else if (fd == STDIN_FILENO)
  {
    return -1; // case for writing to standard input will cause error
  }
  // else
  // {
  //   // case for writing to a file
  // }
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) 
      : "q" (byte));
  return error_code != -1;
}