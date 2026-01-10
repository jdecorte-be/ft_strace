#include "strace.h"
#include "syscalls.h"

const syscall_t			x86_64_syscall[] = X86_64_SYSCALL;
const syscall_t			i386_syscall[] = I386_SYSCALL;
extern const char		*sys_signame[];

t_sys_arch detect_sys_arch(struct user_regs_struct *regs)
{
    if (regs->cs == 0x33)
        return ARCH_X86_64;
    else if (regs->cs == 0x23)
        return ARCH_I386;
    else
        return ARCH_UNKNOWN;
}

void		block_signals(pid_t pid)
{
	int				status;
	sigset_t		set;

	sigemptyset(&set);
	sigprocmask(SIG_SETMASK, &set, NULL);
	waitpid(pid, &status, 0);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGPIPE);
	sigaddset(&set, SIGTERM);
	sigprocmask(SIG_BLOCK, &set, NULL);
}

/*** Handler for x86_64 and i386 ***/

int handle_syscall_x86_64(t_strace *strace, struct user_regs_struct *regs, _Bool is_entry)
{
    unsigned long syscall_num = regs->orig_rax;

    if (regs->rax == -ENOSYS && regs->orig_rax < MAX_X86_64_SYSCALL)
    {
        print_syscall(strace, x86_64_syscall[syscall_num], x86_64_syscall[syscall_num].argc,
            regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9);
    }
    else
    {
        if(x86_64_syscall[syscall_num].type_ret == INT)
            fprintf(stderr, " = %d\n", regs->rax);
        else
            fprintf(stderr, " = %#lx\n", regs->rax);
    }
    return 0; 
}

int handle_syscall_i386(t_strace *strace, struct user_regs_struct *regs, _Bool is_entry)
{
    unsigned long syscall_num = regs->orig_rax;

    if (regs->rax == -ENOSYS && syscall_num < MAX_I386_SYSCALL)
    {
        print_syscall(strace, i386_syscall[syscall_num], i386_syscall[syscall_num].argc,
            regs->rbx, regs->rcx, regs->rdx, regs->rsi, regs->rdi, regs->rbp);
    }
    else
    {
        if (i386_syscall[syscall_num].type_ret == INT)
            fprintf(stderr, " = %d\n", (int)regs->rax);
        else
            fprintf(stderr, " = %#x\n", (unsigned int)regs->rax);
    }
    return 0;
}



int trace_bin(t_strace *strace)
{
    siginfo_t si;
    int status;
    struct user_regs_struct regs;
    struct iovec iov;
    t_sys_arch sys_arch;

    _Bool is_entry = 0;
    _Bool is_print = 0;
    
    if (ptrace(PTRACE_SEIZE, strace->pid, 0, 0) == -1)
        error(EXIT_FAILURE, 0, "ptrace seize failed");
    if (ptrace(PTRACE_INTERRUPT, strace->pid, 0, 0) == -1)
        error(EXIT_FAILURE, 0, "ptrace interrupt failed");

    block_signals(strace->pid);

    while (42)
    {
        if (ptrace(PTRACE_SYSCALL, strace->pid, 0, 0) < 0)
            break;
        if (waitpid(strace->pid, &status, 0) < 0)
            break;

        /* Check for signals */
        if (is_entry && !ptrace(PTRACE_GETSIGINFO, strace->pid, 0, &si) && si.si_signo != SIGTRAP)
        {
            fprintf(stderr, "--- %s ", sys_signame[si.si_signo]);
			print_siginfo(&si);
			fprintf(stderr, " ---\n");
        }


        iov.iov_base = &regs;
        iov.iov_len = sizeof(regs);
        if (ptrace(PTRACE_GETREGSET, strace->pid, NT_PRSTATUS, &iov) == -1)
            break;

        /* Detect architecture */
        sys_arch = detect_sys_arch(&regs);

        switch (sys_arch)
        {
            case ARCH_X86_64: // 64-bit architecture
                if (!is_print)
                {
                    if (!is_entry && regs.orig_rax == 59)
                        is_print = 1;
                    else
                        continue;
                }

                handle_syscall_x86_64(strace, &regs, is_entry);
                is_entry = !is_entry;
                break;
            case ARCH_I386: // 32-bit architecture
                if (!is_print)
                {
                    if (!is_entry && regs.orig_rax == 11)
                        is_print = 1;
                    else
                        continue;
                }
                handle_syscall_x86_64(strace, &regs, is_entry);
                is_entry = !is_entry;
                break;
            default:
                printf("Unknown architecture\n");
                return -1;
        }
    }

    if (!is_entry && is_print)
        fprintf(stderr, " = ?\n");

	if (WIFSIGNALED(status))
	{
		fprintf(stderr, "+++ killed by %s +++\n", sys_signame[WTERMSIG(status)]);
		kill(getpid(), WTERMSIG(status));
	}
	else
		fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));

	return status;
}
