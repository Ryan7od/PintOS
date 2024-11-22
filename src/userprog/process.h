#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <list.h>
#include "threads/synch.h"

typedef int tid_t;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct child_process {
  tid_t tid;                      /* Thread ID of the child */
  struct thread *parent;          /* Pointer to the parent thread */
  struct list_elem elem;          /* List element to add to parent's child list */
  int exit_status;                /* Exit status of the child */
  struct semaphore sema;          /* Semaphore to block parent */
  struct semaphore load_sema;     /* Semaphore to block parent while loading */
  bool dead;                      /* Track if the process should be freed */
  char *file_name;                /* File name to pass to start process */
  bool fail_load;
};

extern struct lock exit_lock;     /* To ensure two threads can't race to exit */

/* Process ID type */
typedef int pid_t;

#endif /* userprog/process.h */
