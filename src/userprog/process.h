#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

#define MAX_OPEN_NR 128
struct file_descriptor {
   struct file* file;
   int cur_pos;
};
extern struct semaphore file_lock;


// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */

   struct process* parent;
   int exit_status;
   int pid;
   bool waited;
   struct semaphore sema_wait;
   struct semaphore sema_mutex;

   struct list children;
   struct list_elem children_node;

   struct file* executable;
   struct file_descriptor fds[MAX_OPEN_NR];
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(int exit_code);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

int get_free_fd(struct process* process);

#endif /* userprog/process.h */
