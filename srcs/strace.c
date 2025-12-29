#include "strace.h"
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>


int exec_bin(int ac, char **av)
{
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
    {
        perror("ptrace");
        return -1;
    }
    printf("Executing target binary: %s\n", av[0]);
    return execvp(av[0], av);
}

int trace_bin()
{
    int status;
    pid_t child = wait(&status);
    if (child == -1)
    {
        perror("wait");
        return -1;
    }
    printf("Tracing the target binary...\n");

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1)
    {
        perror("ptrace(GETREGS)");
        return -1;
    }

    unsigned long orig = regs.orig_rax;

    printf("Original syscall number: %lu\n", orig);

    ptrace(PTRACE_CONT, child, NULL, NULL);
    return 0;
}


