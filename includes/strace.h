#ifndef STRACE_H
#define STRACE_H

#define _GNU_SOURCE
#include <argp.h>
#include <elf.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* System headers */
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "syscalls.h"

#define BUFFER_SIZE 4096
#define MAX_ARGS 6

typedef struct s_stats
{
    unsigned long long calls;
    unsigned long long errors;
    struct timespec total_time;
    const char *name;
} t_stats;

typedef enum e_sys_arch
{
    ARCH_X86_64, // 64-bit architecture
    ARCH_I386,   // 32-bit architecture
    ARCH_UNKNOWN,
} t_sys_arch;

struct arguments
{
    char **target;
    _Bool sum_opt;
};

typedef struct s_strace
{
    struct arguments args;
    t_stats stats_64[MAX_X86_64_SYSCALL];
    t_stats stats_32[MAX_I386_SYSCALL];
    struct timespec start_ts;

    char execve_buffer[BUFFER_SIZE];

    pid_t pid;
    size_t n_env;
} t_strace;

typedef struct syscall_s
{
    char *name;
    int argc;
    int type_args[MAX_ARGS];
    int type_ret;

} syscall_t;

typedef struct i386_user_regs_struct {
	int		ebx;
	int		ecx;
	int		edx;
	int		esi;
	int		edi;
	int		ebp;
	int		eax;
	int		xds;
	int		xes;
	int		xfs;
	int		xgs;
	int		orig_eax;
	int		eip;
	int		xcs;
	int		eflags;
	int		esp;
	int		xss;
} i386_user_regs_struct_t;

void print_summary(t_strace *strace);
void print_syscall(t_strace *strace, syscall_t syscall, int argc, ...);
int trace_bin(t_strace *strace);
void print_siginfo(siginfo_t *si);
void exec_with_path(char **av, char **env);

#endif