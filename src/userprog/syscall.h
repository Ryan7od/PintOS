#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>

#define MAX_OPEN_FILES 128

/* Data structure for file descriptor */
struct file_descriptor {
  int fd;                     /* File descriptor number */
  struct file *file;          /* Pointer to the file structure */
  struct list_elem elem;      /* List element for inclusion in a list */
};

extern struct lock filesys_lock; /* To ensure two threads cant call filesys */

void syscall_init (void);

void fatal_sys_exit (void);
void close_all_files (void);

#endif /* userprog/syscall.h */
