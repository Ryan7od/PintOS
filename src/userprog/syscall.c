#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/kernel/console.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

static int get_user(const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte) UNUSED;

static void get_args (struct intr_frame *f, int *args, int num_args);
static void validate_buffer(const void *buffer, unsigned size);
static void validate_user_pointer(const void *ptr);
static void validate_string(const char *str);
static struct file_descriptor *get_file_descriptor(int fd);

/* System call functions */
static void sys_halt(void);
static void sys_exit(int status);
static pid_t sys_exec(const char *cmd_line);
static int sys_wait(pid_t pid);
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open(const char *file);
static int sys_filesize (int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);

static struct lock filesys_lock;

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_number;
  int args[3];
  if (f == NULL || !is_user_vaddr(f->esp) || f->esp == NULL)
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
    
    case SYS_REMOVE:
      get_args(f, &args[0], 1);
      validate_string((const char *)args[0]);
      f->eax = sys_remove((const char *)args[0]);
      break;

    case SYS_OPEN:
      get_args(f, &args[0], 1);
      validate_string((const char *)args[0]);
      f->eax = sys_open((const char *)args[0]);
      break;

    case SYS_FILESIZE:
      get_args(f, &args[0], 1);
      f->eax = sys_filesize(args[0]);
      break;

    case SYS_READ:
      get_args(f, &args[0], 3);
      validate_buffer((void *)args[1], args[2]);
      f->eax = sys_read(args[0], (void *)args[1], args[2]);
      break;

    case SYS_WRITE:
      get_args(f, args, 3);
      validate_buffer((const void*)args[1], args[2]);
      f->eax = sys_write(args[0], (const void *)args[1], args[2]);
      break;

    case SYS_SEEK:
      get_args(f, &args[0], 2);
      sys_seek(args[0], (unsigned)args[1]);
      break;

    case SYS_TELL:
      get_args(f, &args[0], 1);
      f->eax = sys_tell(args[0]);
      break;

    case SYS_CLOSE:
      get_args(f, &args[0], 1);
      sys_close(args[0]);
      break;

    default:
      // printf("Unknown system call: %d\n", syscall_number);
      sys_exit(-1);
      break;
  }
}

static void 
get_args (struct intr_frame *f, int *args, int num_args)
{
  int *ptr;
  for (int i = 0; i < num_args; i++)
  {
    ptr = (int *)f->esp + i + 1;
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
  if (ptr == NULL || !is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL)
  {
    sys_exit(-1);
  }

  if (get_user((const uint8_t *)ptr) == -1)
  {
    sys_exit (-1);
  }
} 

static void
validate_string(const char *str)
{
  if (str == NULL)
  {
    sys_exit(-1);
  }

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
  printf("halt");
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
  if (file == NULL)
  {
    sys_exit(-1); // Or return false
  }

  bool success;

  lock_acquire(&filesys_lock);
  success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);

  return success;
}

static bool
sys_remove(const char *file)
{
  bool success;
  
  lock_acquire(&filesys_lock);
  success = filesys_remove(file);
  lock_release(&filesys_lock);

  return success;
}

static int
sys_open(const char *file)
{
  struct file *f;
  int fd = -1;
  struct thread *cur = thread_current();
  struct file_descriptor *fd_elem;

  if (file == NULL)
  {
    return -1;
  }

  validate_string(file);

  lock_acquire(&filesys_lock);
  if(list_size(&cur->fd_list) >= MAX_OPEN_FILES) 
  {
    lock_release(&filesys_lock);
    return -1;
  }

  f = filesys_open(file);

  if (f == NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }

  fd_elem = malloc(sizeof(struct file_descriptor));
  if (fd_elem == NULL)
  {
    file_close(f);
    lock_release(&filesys_lock);
    return -1;
  }

  fd_elem->fd = cur->next_fd++;
  fd_elem->file = f;

  list_push_back(&cur->fd_list, &fd_elem->elem);

  fd = fd_elem->fd;

  lock_release(&filesys_lock);

  return fd;
}

static int
sys_filesize(int fd)
{
  struct file_descriptor *fd_elem;
  int size = -1;

  lock_acquire(&filesys_lock);
  fd_elem = get_file_descriptor(fd);
  if (fd_elem != NULL && fd_elem->file != NULL)
  {
    size = file_length(fd_elem->file);
  }
  lock_release(&filesys_lock);

  return size;
}

static int
sys_read(int fd, void *buffer, unsigned size)
{
  struct file_descriptor *fd_elem;
  int bytes_read = -1;

  validate_buffer(buffer, size);

  if (fd == STDIN_FILENO)
  {
    // keyboard
    uint8_t *buf = (uint8_t *)buffer;
    for (unsigned i = 0; i < size; i++)
    {
      buf[i] = input_getc();
    }
    return size;
  }
  else if (fd == STDOUT_FILENO)
  {
    return -1;
  }
  else
  {
    lock_acquire(&filesys_lock);
    fd_elem = get_file_descriptor(fd);

    if (fd_elem != NULL && fd_elem->file != NULL)
    {
      bytes_read = file_read(fd_elem->file, buffer, size);
    }

    lock_release(&filesys_lock);
    return bytes_read;
  }
}

static int
sys_write (int fd, const void *buffer, unsigned size)
{
  struct file_descriptor *fd_elem;
  int bytes_written = -1;

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
  else
  {
    lock_acquire(&filesys_lock);
    fd_elem = get_file_descriptor(fd);

    if (fd_elem != NULL && fd_elem->file != NULL)
    {
      bytes_written = file_write(fd_elem->file, buffer, size);
    }

    lock_release(&filesys_lock);
    return bytes_written;
  }
}

static void
sys_seek(int fd, unsigned position)
{
  struct file_descriptor *fd_elem;

  lock_acquire(&filesys_lock);
  fd_elem = get_file_descriptor(fd);

  if (fd_elem != NULL && fd_elem->file != NULL)
  {
    file_seek(fd_elem->file, position);
  }

  lock_release(&filesys_lock);
}

static unsigned
sys_tell(int fd)
{
  struct file_descriptor *fd_elem;
  unsigned position = (unsigned) -1;

  lock_acquire(&filesys_lock);
  fd_elem = get_file_descriptor(fd);

  if (fd_elem != NULL && fd_elem->file != NULL)
  {
    position = file_tell(fd_elem->file);
  }

  lock_release(&filesys_lock);
  return position;
}

static void
sys_close(int fd)
{
  struct file_descriptor *fd_elem;

  lock_acquire(&filesys_lock);
  fd_elem = get_file_descriptor(fd);

  if (fd_elem != NULL)
  {
    file_close(fd_elem->file);
    list_remove(&fd_elem->elem);
    free(fd_elem); //assuming malloc in open
  }

  lock_release(&filesys_lock);
}


// retrieves the file descriptor structure associated with fd in the current process
static struct file_descriptor *
get_file_descriptor(int fd)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin(&t->fd_list); e != list_end(&t->fd_list); e = list_next(e))
  {
    struct file_descriptor *fd_elem = list_entry(e, struct file_descriptor, elem);
    if (fd_elem->fd == fd)
    {
      return fd_elem;
    }
  }
  return NULL;  // file descriptor not found 
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