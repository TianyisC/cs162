#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "devices/input.h"
#include "kernel/stdio.h"
#include "process.h"

struct semaphore file_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); sema_init(&file_lock, 1); }

static bool checkPointer(void* pointer, size_t len)
{
  uint32_t vpn_start = (uint32_t)pointer >> PGBITS;
  uint32_t vpn_end = (uint32_t)((char*)pointer + len) >> PGBITS;
  size_t num = vpn_end - vpn_start + 1;

  for (size_t i = 0; i < num; i++) {
    uint32_t addr = (vpn_start + i) << PGBITS;
    if (!(is_user_vaddr((void*)addr) && pagedir_get_page(thread_current()->pcb->pagedir, (void*)addr))) {
      return false;
    }
  }
  return true;
}

#define CHECK(pointer, len, rel) do {if (!checkPointer((void*)pointer, len)) {if (rel) sema_up(&file_lock); process_exit(-1);} } while(0);

bool sys_create(const char* file_name, unsigned initial_size) {
  CHECK(file_name, 4, 1); //TODO: check string
  return filesys_create(file_name, initial_size);
}

bool sys_remove(const char* file_name) {
  CHECK(file_name, 4, 1); //TODO: check string
  return filesys_remove(file_name);
}

int sys_open(const char* file_name) {
  CHECK(file_name, 4, 1); //TODO: check string
  struct file* file = filesys_open(file_name);
  if (!file) return -1;

  int fd = get_free_fd(thread_current()->pcb);
  if (fd == -1) return fd;
  thread_current()->pcb->fds[fd].file = file;
  return fd;
}

void sys_close(int fd) {
  if (fd < 3 || fd >= MAX_OPEN_NR) return;

  struct file* file = thread_current()->pcb->fds[fd].file;
  if (!file) return;

  file_close(file);
  thread_current()->pcb->fds[fd].file = NULL;
  thread_current()->pcb->fds[fd].cur_pos = 0;

}

int sys_filesize(int fd) {
  if (fd < 3 || fd >= MAX_OPEN_NR) return -1;

  struct file* file = thread_current()->pcb->fds[fd].file;
  if (!file) return -1;

  struct inode* i = file_get_inode(file);
  if (!i) return -1;

  return inode_length(i);
}

int sys_read(int fd, void* buffer, unsigned size) {
  CHECK(buffer, size, 1);
  if (fd < 0 || fd >= MAX_OPEN_NR) return -1;

  if (fd == STDIN_FILENO) {
    return input_getc();
  } else if (fd == STDOUT_FILENO) {
    return -1;
  }

  struct file* file = thread_current()->pcb->fds[fd].file;
  if (!file) return -1;

  
  int read = file_read_at(file, buffer, size, thread_current()->pcb->fds[fd].cur_pos);
  thread_current()->pcb->fds[fd].cur_pos += read;
  return read;
}

int sys_write(int fd, const void* buffer, unsigned size) {
  CHECK(buffer, size, 1);
  if (fd < 0 || fd >= MAX_OPEN_NR) return -1;

  if (fd == STDIN_FILENO) {
    return -1;
  } else if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  }

  struct file* file = thread_current()->pcb->fds[fd].file;
  if (!file) return -1;

  int wrote = file_write(file, buffer, size);
  thread_current()->pcb->fds[fd].cur_pos += wrote;
  return wrote;
}

unsigned sys_tell(int fd) {
  if (fd < 3 || fd >= MAX_OPEN_NR) return 0;

  struct file* file = thread_current()->pcb->fds[fd].file;
  if (!file) return -1;

  return thread_current()->pcb->fds[fd].cur_pos;
}

void sys_seek(int fd, unsigned position) {
  if (fd < 3 || fd >= MAX_OPEN_NR) return;

  struct file* file = thread_current()->pcb->fds[fd].file;
  if (!file) return;

  thread_current()->pcb->fds[fd].cur_pos = position;
}
 

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  CHECK(args, 4, 0); 
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    CHECK(&args[1], 4, 0);
    f->eax = args[1];
    process_exit(args[1]);
  } else if (args[0] == SYS_PRACTICE) {
    CHECK(&args[1], 4, 0);
    f->eax = (int)args[1] + 1;
  } else if (args[0] == SYS_HALT) {
    f->eax = 0;
    shutdown_power_off();
  } else if (args[0] == SYS_EXEC) {
    CHECK(&args[1], 4, 0);
    CHECK(args[1], 4, 0); //TODO: check string
    f->eax = process_execute((char*)args[1]);
  } else if (args[0] == SYS_WAIT) {
    CHECK(&args[1], 4, 0);
    f->eax = process_wait(args[1]);
  } 
  
  

  else if (args[0] == SYS_CREATE) {
    CHECK(&args[1], 4, 0);
    CHECK(&args[2], 4, 0);
    sema_down(&file_lock);
    f->eax = sys_create((const char*)args[1], args[2]);
    sema_up(&file_lock);
  } else if (args[0] == SYS_REMOVE) {
    CHECK(&args[1], 4, 0);
    sema_down(&file_lock);
    f->eax = sys_remove((const char*)args[1]);
    sema_up(&file_lock);
  } else if (args[0] == SYS_OPEN) {
    CHECK(&args[1], 4, 0);
    sema_down(&file_lock);
    f->eax = sys_open((const char*)args[1]);
    sema_up(&file_lock);
  } else if (args[0] == SYS_FILESIZE) {
    CHECK(&args[1], 4, 0);
    sema_down(&file_lock);
    f->eax = sys_filesize(args[1]);
    sema_up(&file_lock);
  } else if (args[0] == SYS_READ) {
    CHECK(&args[1], 4, 0);
    CHECK(&args[2], 4, 0);
    CHECK(&args[3], 4, 0);
    sema_down(&file_lock);
    f->eax = sys_read(args[1], (char*)args[2], args[3]);
    sema_up(&file_lock);
  } else if (args[0] == SYS_WRITE) {
    CHECK(&args[1], 4, 0);
    CHECK(&args[2], 4, 0);
    CHECK(&args[3], 4, 0);
    sema_down(&file_lock);
    f->eax = sys_write(args[1], (char*)args[2], args[3]);
    sema_up(&file_lock);
  } else if (args[0] == SYS_SEEK) {
    CHECK(&args[1], 4, 0);
    CHECK(&args[2], 4, 0);
    sema_down(&file_lock);
    sys_seek(args[1], args[2]);
    sema_up(&file_lock);
  } else if (args[0] == SYS_TELL) {
    CHECK(&args[1], 4, 0);
    sema_down(&file_lock);
    f->eax = sys_tell(args[1]);
    sema_up(&file_lock);
  } else if (args[0] == SYS_CLOSE) {
    CHECK(&args[1], 4, 0);
    sema_down(&file_lock);
    sys_close(args[1]);
    sema_up(&file_lock);
  } 
  
}
