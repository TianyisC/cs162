#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static bool checkPointer(void* pointer)
{
  return is_user_vaddr(pointer) && pagedir_get_page(thread_current()->pcb->pagedir, pointer);
}

#define CHECK(pointer) do {if (!checkPointer(pointer)) {process_exit();} } while(0);

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  CHECK(args);
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    thread_current()->pcb->exit_status = args[1];
    process_exit();
  } else if (args[0] == SYS_PRACTICE) {
    f->eax = (int)args[1] + 1;
  } else if (args[0] == SYS_HALT) {
    f->eax = 0;
    shutdown_power_off();
  } else if (args[0] == SYS_EXEC) {
    char* path = args[1];
    CHECK(path);
    f->eax = process_execute(path);
  } else if (args[0] == SYS_WAIT) {
    f->eax = process_wait(args[1]);
  } 
  
  
  
  else if (args[0] == SYS_CREATE) {

  } else if (args[0] == SYS_REMOVE) {

  } else if (args[0] == SYS_OPEN) {

  } else if (args[0] == SYS_FILESIZE) {

  } else if (args[0] == SYS_READ) {

  } else if (args[0] == SYS_WRITE) {

  } else if (args[0] == SYS_SEEK) {

  } else if (args[0] == SYS_TELL) {

  } else if (args[0] == SYS_CLOSE) {

  } 
  
}
