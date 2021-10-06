#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H



void syscall_init(void);

static void syscall_handler(struct intr_frame *);
void sys_exit(int status);
tid_t sys_exec(const char *cmd_line);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close(int fd);

#endif /* userprog/syscall.h */
