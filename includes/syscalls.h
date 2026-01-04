#ifndef SYSCALLS_H
# define SYSCALLS_H

# include "syscall_tables/syscall64.h"
# include "syscall_tables/syscall32.h"


# define MAX_ARGS 6

# define MODE_64BITS		0
# define MODE_32BITS		1

# define INT				1
# define LONG				2
# define ULONG				3
# define PTR				4
# define STR				5
# define FLAG_OPEN			6
# define FLAG_OPENAT		7
# define FLAG_PROT			8
# define FLAG_MMAP			9
# define STRUCT_STAT		10
# define STRUCT_POLL		11
# define STRUCT_SIGACT		12
# define STRUCT_SIGSET		13
# define STRUCT_SIGINF		14
# define STRUCT_IOVEC		15
# define STRUCT_FDSET		16
# define STRUCT_TIMEVAL		17
# define STRUCT_TIMEZONE	18
# define STRUCT_TIMESPEC	19
# define STRUCT_SHMID		20
# define STRUCT_SOCKADDR	21
# define STRUCT_MSGHDR		22
# define STRUCT_RUSAGE		23
# define STRUCT_UTSNAME		24
# define STRUCT_SEMBUF		25
# define STRUCT_MSGID		26
# define STRUCT_LINUX_DIR	27
# define STRUCT_RLIMIT		28
# define STRUCT_SYSINFO		29
# define STRUCT_SIGINFO		30
# define STRUCT_TMS			31
# define PIPE				32
# define SV					33
# define KEY				34
# define MODE				35
# define CLOCK				36
# define PTRACE				37
# define ID_T				38
# define DEV				39
# define TIME				40
# define SIGNAL				41
# define ARGV				42
# define ENVP				43

#endif