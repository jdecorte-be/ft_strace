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

int exec_bin(int ac, char **av)
{
    char *args[ac + 1];
    memcpy(args, av, ac * sizeof(char*));
    args[ac] = NULL;
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    return execvp(args[0], args);
}

int trace_bin()
{
    return 0;
}


int main(int ac, char **av)
{
    if (ac < 2)
    {
        fprintf(stderr, "strace: must have PROG [ARGS] or -p PID\n");
        fprintf(stderr, "Try 'strace -h' for more information.\n");
        return 1;
    }   

    pid_t pid = fork();
    if(pid == 0)
        return exec_bin(ac, av);
    else
        return trace_bin();
}