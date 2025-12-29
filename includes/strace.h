#ifndef STRACE_H
# define STRACE_H

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <signal.h>
#include <string.h>
#include <argp.h>
#include <errno.h>

struct arguments
{
    char **target;
    _Bool sum_opt;

};

typedef struct s_strace
{
    struct arguments args;

    
}   t_strace;



#endif