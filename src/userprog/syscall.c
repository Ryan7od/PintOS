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

static int get_user (const uint8_t *uaddr);

static bool put_user (uint8_t *udst, uint8_t byte) UNUSED;
static void get_args (struct intr_frame *f, int *args, int num_args);
static void validate_buffer (const void *buffer, unsigned size);
static void validate_user_pointer (const void *ptr);
static void validate_string (const char *str);
static struct file_descriptor *get_file_descriptor (int fd);

/* System call handler functions */
static int sys_halt (struct intr_frame *f);
static int sys_exit (struct intr_frame *f);
static int sys_exec (struct intr_frame *f);
static int sys_wait (struct intr_frame *f);
static int sys_create (struct intr_frame *f);
static int sys_remove (struct intr_frame *f);
static int sys_open (struct intr_frame *f);
static int sys_filesize (struct intr_frame *f);
static int sys_read (struct intr_frame *f);
static int sys_write (struct intr_frame *f);
static int sys_seek (struct intr_frame *f);
static int sys_tell (struct intr_frame *f);
static int sys_close (struct intr_frame *f);

struct lock filesys_lock;

/* Array of system call handler functions indexed by system call numbers */
#define SYS_CALL_NUMBER 13  // Total number of syscalls handled
typedef int (*syscall_func) (struct intr_frame *);
static syscall_func syscall_table[SYS_CALL_NUMBER];
        
void
syscall_init (void) {
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  
  /* Initialize the system call handler function table */
  syscall_table[ SYS_HALT ] = sys_halt;
  syscall_table[ SYS_EXIT ] = sys_exit;
  syscall_table[ SYS_EXEC ] = sys_exec;
  syscall_table[ SYS_WAIT ] = sys_wait;
  syscall_table[ SYS_CREATE ] = sys_create;
  syscall_table[ SYS_REMOVE ] = sys_remove;
  syscall_table[ SYS_OPEN ] = sys_open;
  syscall_table[ SYS_FILESIZE ] = sys_filesize;
  syscall_table[ SYS_READ ] = sys_read;
  syscall_table[ SYS_WRITE ] = sys_write;
  syscall_table[ SYS_SEEK ] = sys_seek;
  syscall_table[ SYS_TELL ] = sys_tell;
  syscall_table[ SYS_CLOSE ] = sys_close;
}

/* Function that handles all syscall calls from threads, reading necessary
 * arguments from the stack and performing different operations based on the
 * given syscall number */
static void
syscall_handler (struct intr_frame *f) {
  int syscall_number;
  
  validate_user_pointer (f->esp);
  
  /* Retrieve the system call number from the stack */
  syscall_number = *(int *)f->esp;
  
  /* Validate the system call number */
  if (syscall_number < 0 || syscall_number >= SYS_CALL_NUMBER ||
      syscall_table[ syscall_number ] == NULL) {
    fatal_sys_exit (); // Invalid system call number
  }
  
  /* Call the appropriate system call handler */
  int return_value = syscall_table[ syscall_number ] (f);
  f->eax = return_value;
}

/* System call handler implementations */

/* Completely shuts down pintos */
static int
sys_halt (struct intr_frame *f UNUSED) {
  shutdown_power_off ();
  return 0;
}

/* Exits the current thread gracefully */
static int
sys_exit (struct intr_frame *f) {
  int args[1];
  get_args (f, args, 1);
  int status = args[ 0 ];
  
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
  return 0;
}

/* Function to be called for immediate exit fail */
void
fatal_sys_exit (void) {
  struct thread *cur = thread_current ();
  cur->exit_status = -1;
  
  /* Print exit status */
  printf ("%s: exit(%d)\n", cur->name, -1);
  thread_exit ();
}

/* Opens a new thread based on an executable file */
static int
sys_exec (struct intr_frame *f) {
  int args[1];
  get_args (f, args, 1);
  const char *cmd_line = (const char *)args[ 0 ];
  
  validate_string (cmd_line);
  
  return process_execute (cmd_line);
}

/* Waits on a child process */
static int
sys_wait (struct intr_frame *f) {
  int args[1];
  get_args (f, args, 1);
  pid_t pid = args[ 0 ];
  
  return process_wait (pid);
}

/* Creates a new file */
static int
sys_create (struct intr_frame *f) {
  int args[2];
  get_args (f, args, 2);
  const char *file = (const char *)args[ 0 ];
  unsigned initial_size = (unsigned)args[ 1 ];
  
  validate_string (file);
  
  lock_acquire (&filesys_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  
  return success;
}

/* Delete a file */
static int
sys_remove (struct intr_frame *f) {
  int args[1];
  get_args (f, args, 1);
  const char *file = (const char *)args[ 0 ];
  
  validate_string (file);
  
  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file);
  lock_release (&filesys_lock);
  
  return success;
}

/* Open a file */
static int
sys_open (struct intr_frame *f) {
  int args[1];
  get_args (f, args, 1);
  const char *file = (const char *)args[ 0 ];
  
  validate_string (file);
  
  struct file *file_obj;
  int fd = -1;
  struct thread *cur = thread_current ();
  struct file_descriptor *fd_elem;
  
  lock_acquire (&filesys_lock);
  
  if (list_size (&cur->fd_list) >= MAX_OPEN_FILES) {
    lock_release (&filesys_lock);
    return -1;
  }
  
  file_obj = filesys_open (file);
  
  if (file_obj == NULL) {
    lock_release (&filesys_lock);
    return -1;
  }
  
  fd_elem = malloc (sizeof (struct file_descriptor));
  if (fd_elem == NULL) {
    file_close (file_obj);
    lock_release (&filesys_lock);
    return -1;
  }
  
  fd_elem->fd = cur->next_fd++;
  fd_elem->file = file_obj;
  list_push_back (&cur->fd_list, &fd_elem->elem);
  
  fd = fd_elem->fd;
  lock_release (&filesys_lock);
  
  return fd;
}

/* Find the size of a file */
static int
sys_filesize (struct intr_frame *f) {
  int args[1];
  get_args (f, args, 1);
  int fd = args[ 0 ];
  
  struct file_descriptor *fd_elem;
  int size = -1;
  
  lock_acquire (&filesys_lock);
  fd_elem = get_file_descriptor (fd);
  if (fd_elem != NULL && fd_elem->file != NULL) {
    size = file_length (fd_elem->file);
  }
  lock_release (&filesys_lock);
  
  return size;
}

/* Read a file */
static int
sys_read (struct intr_frame *f) {
  int args[3];
  get_args (f, args, 3);
  int fd = args[ 0 ];
  void *buffer = (void *)args[ 1 ];
  unsigned size = (unsigned)args[ 2 ];
  
  validate_buffer (buffer, size);
  
  int bytes_read = -1;
  
  if (fd == STDIN_FILENO) {
    uint8_t *buf = (uint8_t *)buffer;
    for (unsigned i = 0; i < size; i++) {
      buf[ i ] = input_getc ();
    }
    bytes_read = size;
  } else if (fd == STDOUT_FILENO) {
    bytes_read = -1;
  } else {
    lock_acquire (&filesys_lock);
    struct file_descriptor *fd_elem = get_file_descriptor (fd);
    
    if (fd_elem != NULL && fd_elem->file != NULL) {
      bytes_read = file_read (fd_elem->file, buffer, size);
    }
    lock_release (&filesys_lock);
  }
  
  return bytes_read;
}

/* Write to a file */
static int
sys_write (struct intr_frame *f) {
  int args[3];
  get_args (f, args, 3);
  int fd = args[ 0 ];
  const void *buffer = (const void *)args[ 1 ];
  unsigned size = (unsigned)args[ 2 ];
  
  validate_buffer (buffer, size);
  
  int bytes_written = -1;
  
  if (fd == STDOUT_FILENO) {
    putbuf (buffer, size);
    bytes_written = size;
  } else if (fd == STDIN_FILENO) {
    bytes_written = -1;
  } else {
    lock_acquire (&filesys_lock);
    struct file_descriptor *fd_elem = get_file_descriptor (fd);
    
    if (fd_elem != NULL && fd_elem->file != NULL) {
      bytes_written = file_write (fd_elem->file, buffer, size);
    }
    lock_release (&filesys_lock);
  }
  
  return bytes_written;
}

/* Seek a file */
static int
sys_seek (struct intr_frame *f) {
  int args[2];
  get_args (f, args, 2);
  int fd = args[ 0 ];
  unsigned position = (unsigned)args[ 1 ];
  
  lock_acquire (&filesys_lock);
  struct file_descriptor *fd_elem = get_file_descriptor (fd);
  
  if (fd_elem != NULL && fd_elem->file != NULL) {
    file_seek (fd_elem->file, position);
  }
  lock_release (&filesys_lock);
  
  return 0;
}

/* Tell a file */
static int
sys_tell (struct intr_frame *f) {
  int args[1];
  get_args (f, args, 1);
  int fd = args[ 0 ];
  
  unsigned position = (unsigned)-1;
  
  lock_acquire (&filesys_lock);
  struct file_descriptor *fd_elem = get_file_descriptor (fd);
  
  if (fd_elem != NULL && fd_elem->file != NULL) {
    position = file_tell (fd_elem->file);
  }
  lock_release (&filesys_lock);
  
  return position;
}

/* Close a file */
static int
sys_close (struct intr_frame *f) {
  int args[1];
  get_args (f, args, 1);
  int fd = args[ 0 ];
  
  lock_acquire (&filesys_lock);
  struct file_descriptor *fd_elem = get_file_descriptor (fd);
  
  if (fd_elem != NULL) {
    file_close (fd_elem->file);
    list_remove (&fd_elem->elem);
    free (fd_elem);
  }
  lock_release (&filesys_lock);
  
  return 0;
}

/* Helper functions */

/* Load arguments from the stack */
static void
get_args (struct intr_frame *f, int *args, int num_args) {
  int *ptr;
  for (int i = 0; i < num_args; i++) {
    ptr = (int *)f->esp + i + 1;
    validate_user_pointer ((const void *)ptr);
    args[ i ] = *ptr;
  }
}

static void
validate_buffer (const void *buffer, unsigned size) {
  char *buf = (char *)buffer;
  for (unsigned i = 0; i < size; i++) {
    validate_user_pointer ((const void *)(buf + i));
  }
}

static void
validate_user_pointer (const void *ptr) {
  if (ptr == NULL || !is_user_vaddr (ptr) ||
      pagedir_get_page (thread_current ()->pagedir, ptr) == NULL) {
    fatal_sys_exit ();
  }
}

static void
validate_string (const char *str) {
  if (str == NULL) {
    fatal_sys_exit ();
  }
  
  while (true) {
    validate_user_pointer ((const void *)str);
    if (*str == '\0') {
      break;
    }
    str++;
  }
}

static struct file_descriptor *
get_file_descriptor (int fd) {
  struct thread *t = thread_current ();
  struct list_elem *e;
  
  for (e = list_begin (&t->fd_list);
       e != list_end (&t->fd_list); e = list_next (e)) {
    struct file_descriptor *fd_elem = list_entry (e,
    struct file_descriptor, elem);
    if (fd_elem->fd == fd) {
      return fd_elem;
    }
  }
  return NULL;  // file descriptor not found
}

/* Function to close all open files for the current process */
void
close_all_files (void) {
  struct thread *cur = thread_current ();
  struct list_elem *e;
  
  lock_acquire (&filesys_lock);
  while (!list_empty (&cur->fd_list)) {
    e = list_pop_front (&cur->fd_list);
    struct file_descriptor *fd_elem = list_entry (e,
    struct file_descriptor, elem);
    file_close (fd_elem->file);
    free (fd_elem);
  }
  lock_release (&filesys_lock);
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user (const uint8_t *uaddr) {
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
          : "=&a" (error_code), "=m" (*udst)
          : "q" (byte));
  return error_code != -1;
}
