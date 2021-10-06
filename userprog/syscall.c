#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "string.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "userprog/process.h"


#define MAX_FILE_NAME 15

typedef int tid_t;

static bool check_addr(const void *uaddr);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

struct lock thread_lock;

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

    // Init lock
    lock_init(&thread_lock);
}

void sys_exit(int status) {
    struct thread *cur = thread_current();
    cur->exitStatus = status;

    // Remove args from cmdline leaving only the name
    for(int i = 0;(unsigned) i < strlen(cur->name); i++) {
        if(cur->name[i] == ' ') {
            cur->name[i] = '\0';
            break;
        }
    }

    // Print name and status
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

bool sys_create(const char *file, unsigned initial_size) {
    // Check if file is valid
    if(check_addr(file)) {
        if(get_user((void*) file) == -1) {
            sys_exit(-1);
        }
    } else {
        sys_exit(-1);
    }
    if (file == NULL) {
        sys_exit(-1);
    }
    if (strlen(file) == 0 || strlen(file) > MAX_FILE_NAME) {
        return false;
    }

    // Create file
    bool created = false;
    lock_acquire(&thread_lock);
    created = filesys_create(file, initial_size);
    lock_release(&thread_lock);
    return created;
}

bool sys_remove(const char *file) {
    // Check if file is valid name
    if (file == NULL || strlen(file) == 0) {
        return false;
    }

    // Check if address is valid
    if(check_addr(file)) {
        if(get_user((void*) file) == -1) {
            sys_exit(-1);
        }
    } else {
        sys_exit(-1);
    }

    // Remove file
    bool removed = false;
    lock_acquire(&thread_lock);
    removed = filesys_remove(file);
    lock_release(&thread_lock);
    return removed;
}

int sys_open(const char *file) {
    // Check if file is valid name
    if (file == NULL || strlen(file) == 0) {
        return -1;
    }

    // Check if address is valid
    if(is_user_vaddr(file)) {
        if(get_user((void*) file) == -1) {
            sys_exit(-1);
        }
    } else {
        sys_exit(-1);
    }

    // Open file
    int fd = -1;
    lock_acquire(&thread_lock);
    struct thread* cur = thread_current();
    struct file* new_file = filesys_open(file);
    if (new_file != NULL) {
        cur->fdtab[cur->nextfd] = new_file;

        fd = cur->nextfd;
        cur->nextfd++;
    }
    lock_release(&thread_lock);
    return fd;
}

int sys_filesize(int fd) {
    struct thread* cur = thread_current();

    // Check if valid fd
    if (fd >= cur->nextfd) {
        sys_exit(-1);
    }

    // struct file* file = cur->fdtab[fd];      // DELETE!!!
    return file_length(cur->fdtab[fd]);
}

int sys_read(int fd, void *buffer, unsigned size) {
    struct thread* cur = thread_current();

    // Check if valid fd
    if (fd >= cur->nextfd) {
        sys_exit(-1);
    }

    struct file* file = cur->fdtab[fd];

    // Check if file is valid name
    if (file == NULL) {
        return -1;
    }

    // Check if address is valid
    if(check_addr(buffer)) {
        if(get_user(buffer) == -1) {
            sys_exit(-1);
        }
    } else {
        sys_exit(-1);
    }

    lock_acquire(&thread_lock);
    int count = 0;

    // Read from stdin or file
    if (fd == 0) {
        uint8_t* ptr = buffer;
        uint8_t c = input_getc();

        // Get chars until reach size or end
        while ((unsigned) count < size && c != 0) {
            count++;
            *ptr = c;
            ptr++;
            c = input_getc();
        }
        *ptr = 0;
    } else {
        count = file_read(file, buffer, size);
    }
    lock_release(&thread_lock);

    return count;
}

int sys_write(int fd, const void *buffer, unsigned size) {
    struct thread *cur = thread_current();

    // Check valid fd
    if (fd >= cur->nextfd) {
        sys_exit(-1);
    }

    // Check valid address
    if(check_addr(buffer)) {
        if(get_user(buffer) == -1) {
            sys_exit(-1);
        }
    } else {
        sys_exit(-1);
    }

    int ret_size;
    lock_acquire(&thread_lock);

    // Write to stdout or file
    if(fd == 1) {
        putbuf(buffer, size);
        ret_size = size;
    } else {
        ret_size = file_write(cur->fdtab[fd], buffer, size);
    }
    lock_release(&thread_lock);
    return ret_size;
}

void sys_seek(int fd, unsigned position) {
    struct thread* cur = thread_current();

    // Check valid fd
    if (fd >= cur->nextfd) {
        sys_exit(-1);
    }

    struct file* file = cur->fdtab[fd];

    // Check valid position
    if (position > (unsigned) file_length(file)) {
        sys_exit(-1);
    }

    file_seek(file, position);
}

unsigned sys_tell (int fd) {
    struct thread* cur = thread_current();

    // Check valid fd
    if (fd >= cur->nextfd) {
        sys_exit(-1);
    }

    return file_tell(cur->fdtab[fd]);
}

void sys_close(int fd) {
    struct thread* cur = thread_current();

    // Check valid fd
    if (fd >= cur->nextfd) {
        sys_exit(-1);
    }

    // Close file
    struct file* file = cur->fdtab[fd];
    file_close(file);

    // Shift following files
    for (int i = fd; i < cur->nextfd; i++) {
        cur->fdtab[i] = cur->fdtab[i + 1];
    }
    cur->nextfd--;
}

// Check if address is in user space
static bool check_addr(const void *uaddr) {
    if(uaddr < PHYS_BASE) {
        return true;
    }
    return false;
}

/* Reads a byte at user virtual address UADDR.
    UADDR must be below PHYS_BASE.
    Returns the byte value if successful, -1 if a segfault
    occurred. */
static int get_user (const uint8_t *uaddr) {
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
    return result;
}

static void syscall_handler(struct intr_frame *f) {
    int callNum = (int) *((int *)f->esp);

    switch(callNum) {
        case SYS_HALT:
            /* Halt the operating system. */
            shutdown_power_off();
            break;
        case SYS_EXIT:
            /* Terminate this process. */
            sys_exit((int) *((int *)(f->esp+4)));
            break;
        case SYS_EXEC:
            /* Start another process. */
            break;
        case SYS_WAIT:
            /* Wait for a child process to die. */
            break;
        case SYS_CREATE:
            /* Create a file. */
            f->eax = sys_create((const char*) *((const char**)(f->esp+4)),
                                (unsigned) *((unsigned*)(f->esp+8)));
            break;
        case SYS_REMOVE:
            /* Delete a file. */
            f->eax = sys_remove((const char*) *((const char**)(f->esp+4)));
            break;
        case SYS_OPEN:
            /* Open a file. */
            f->eax = sys_open((const char*) *((const char**)(f->esp+4)));
            break;
        case SYS_FILESIZE:
            /* Obtain a file's size. */
            f->eax = sys_filesize((int) *((int *)(f->esp+4)));
            break;
        case SYS_READ:
            /* Read from a file. */
            f->eax = sys_read((int) *((int *)(f->esp+4)),
                                (void*) *((void**)(f->esp+8)),
                                (unsigned) *((unsigned*)(f->esp+12)));
            break;
        case SYS_WRITE:
            /* Write to a file. */
            f->eax = sys_write((int) *((int *)(f->esp+4)),
                                (const void*) *((const void**)(f->esp+8)),
                                (unsigned) *((unsigned*)(f->esp+12)));
            break;
        case SYS_SEEK:
            /* Change position in a file. */
            sys_seek((int) *((int *)(f->esp+4)),
                    (unsigned) *((unsigned*)(f->esp+8)));
            break;
        case SYS_TELL:
            /* Report current position in a file. */
            f->eax = sys_tell((int) *((int *)(f->esp+4)));
            break;
        case SYS_CLOSE:
            /* Close a file. */
            sys_close((int) *((int *)(f->esp+4)));
            break;
        default:
            /* Error as this shouldn't happen with lab 2 - possibly change for 3 and 4 */
            break;
    }

}
