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

int trace_bin(t_strace *strace)
{
    int status;
    int is_entry = 1;
    struct user_regs_struct regs;

    waitpid(strace->child, &status, 0);

    ptrace(PTRACE_SETOPTIONS, strace->child, 0, PTRACE_O_TRACESYSGOOD);

    while (1) {
        if (ptrace(PTRACE_SYSCALL, strace->child, 0, 0) == -1) break;
        waitpid(strace->child, &status, 0);

        if (WIFEXITED(status)) break;

        if (ptrace(PTRACE_GETREGS, strace->child, 0, &regs) == -1) break;

        if (is_entry) {
            printf("SYSCALL %llu(%llu, %llu, %llu) ", 
                   regs.orig_rax, regs.rdi, regs.rsi, regs.rdx);
            is_entry = 0;
        } else {
            printf("= %lld\n", (long long)regs.rax);
            is_entry = 1;
        }
    }
    printf("+++ exited with status %d +++\n", WEXITSTATUS(status));
}


