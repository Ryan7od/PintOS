#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct child_process {
  tid_t tid;                      // Thread ID of the child
  struct thread *parent;          // Pointer to the parent thread
  bool parent_alive;              // Flag indicating if the parent is alive
  struct list_elem elem;          // List element to add to parent's child list
  int exit_status;
  struct semaphore sema;
  // Add other fields as necessary (e.g., exit status)
};

/* Process ID type */
typedef int pid_t;

#endif /* userprog/process.h */
