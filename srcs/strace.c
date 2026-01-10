#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/ptrace.h> // For PTRACE_O_TRACESYSGOOD

#include "strace.h"
#include "syscalls.h"

/* Global tables */
const syscall_t			x86_64_syscall[] = X86_64_SYSCALL;
const syscall_t			i386_syscall[] = I386_SYSCALL;
extern const char		*sys_signame[];

/* Helper: Detect Architecture */
t_sys_arch detect_sys_arch(struct user_regs_struct *regs)
{
    if (regs->cs == 0x33)
        return ARCH_X86_64;
    else if (regs->cs == 0x23)
        return ARCH_I386;
    else
        return ARCH_UNKNOWN;
}

/* Helper: Block signals in the tracer so Ctrl+C doesn't kill us immediately */
void block_signals(pid_t pid)
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

/* 
** Generalized Syscall Handler 
** Handles both x86_64 and i386, argument masking, and error printing.
*/
void handle_syscall(t_strace *strace, struct user_regs_struct *regs, t_sys_arch arch, _Bool is_entry)
{
    const syscall_t *table;
    unsigned long syscall_num = regs->orig_rax;
    unsigned long max_syscall;
    unsigned long args[6];
    
    // 1. Setup Architecture Specifics
    if (arch == ARCH_X86_64)
    {
        table = x86_64_syscall;
        max_syscall = MAX_X86_64_SYSCALL;
        
        // System V AMD64 ABI
        args[0] = regs->rdi; args[1] = regs->rsi; args[2] = regs->rdx;
        args[3] = regs->r10; args[4] = regs->r8;  args[5] = regs->r9;
    }
    else if (arch == ARCH_I386)
    {
        table = i386_syscall;
        max_syscall = MAX_I386_SYSCALL;
        
        // i386 ABI (passed in registers). 
        // Cast to uint32_t to mask upper bits.
        args[0] = (uint32_t)regs->rbx; args[1] = (uint32_t)regs->rcx; args[2] = (uint32_t)regs->rdx;
        args[3] = (uint32_t)regs->rsi; args[4] = (uint32_t)regs->rdi; args[5] = (uint32_t)regs->rbp;
    }
    else
    {
        return; // Unknown architecture
    }

    if (syscall_num >= max_syscall)
        return; // Safety check

    if (strace->args.sum_opt)
    {
        t_stats *stats = (arch == ARCH_X86_64) ? &strace->stats_64[syscall_num] : &strace->stats_32[syscall_num];
        
        if (is_entry)
        {
            clock_gettime(CLOCK_MONOTONIC, &strace->start_ts);
            stats->calls++;
            stats->name = table[syscall_num].name;
        }
        else
        {
            struct timespec end_ts, diff;
            clock_gettime(CLOCK_MONOTONIC, &end_ts);
            
            diff.tv_sec = end_ts.tv_sec - strace->start_ts.tv_sec;
            diff.tv_nsec = end_ts.tv_nsec - strace->start_ts.tv_nsec;
            if (diff.tv_nsec < 0) {
                diff.tv_sec--;
                diff.tv_nsec += 1000000000;
            }
            
            stats->total_time.tv_sec += diff.tv_sec;
            stats->total_time.tv_nsec += diff.tv_nsec;
            if (stats->total_time.tv_nsec >= 1000000000) {
                stats->total_time.tv_sec++;
                stats->total_time.tv_nsec -= 1000000000;
            }

            long long ret = (long long)regs->rax;
            if (ret > -4096 && ret < 0)
                stats->errors++;
        }
        return;
    }

    // 2. Print Logic
    if (is_entry)
    {
        // --- SYSCALL ENTRY ---
        print_syscall(strace, table[syscall_num], table[syscall_num].argc,
                      args[0], args[1], args[2], args[3], args[4], args[5]);
    }
    else
    {
        // --- SYSCALL EXIT ---
        long long ret = (long long)regs->rax;

        // Check for Errors: Linux kernel errors are -1 to -4095
        if (ret > -4096 && ret < 0)
        {
            // Print error (e.g. " = -1 EBADF (Bad file descriptor)")
            fprintf(stderr, " = -1 E%lld (%s)\n", -ret, strerror(-ret));
        }
        else
        {
            // Print Success
            if (table[syscall_num].type_ret == INT)
            {
                if (arch == ARCH_I386)
                    fprintf(stderr, " = %d\n", (int)regs->rax);
                else
                    fprintf(stderr, " = %d\n", (int)regs->rax);
            }
            else
            {
                // Print Pointers / Hex
                if (arch == ARCH_I386)
                    fprintf(stderr, " = %#x\n", (unsigned int)regs->rax);
                else
                    fprintf(stderr, " = %#lx\n", regs->rax);
            }
        }
    }
}

/*
** Main Loop
*/
int trace_bin(t_strace *strace)
{
    int status;
    int sig = 0; // Signal to inject back into child
    struct user_regs_struct regs;
    struct iovec iov;
    siginfo_t si;
    t_sys_arch sys_arch;

    _Bool is_entry = 1; // 1 = Entering syscall, 0 = Exiting
    _Bool is_print = 0; // 0 = Waiting for execve, 1 = Printing enabled

    // 1. Seize the process
    if (ptrace(PTRACE_SEIZE, strace->pid, 0, 0) == -1)
        error(EXIT_FAILURE, 0, "ptrace seize failed");
    
    // 2. Interrupt to apply options
    if (ptrace(PTRACE_INTERRUPT, strace->pid, 0, 0) == -1)
        error(EXIT_FAILURE, 0, "ptrace interrupt failed");

    block_signals(strace->pid);

    ptrace(PTRACE_SETOPTIONS, strace->pid, 0, PTRACE_O_TRACESYSGOOD);


    while (42)
    {
        // Pass 'sig' (if any) back to child
        if (ptrace(PTRACE_SYSCALL, strace->pid, 0, sig) < 0)
            break;
        
        if (waitpid(strace->pid, &status, 0) < 0)
            break;

        // Reset injected signal immediately
        sig = 0;

        // Check if child exited or was killed
        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;

        // Check if stopped
        if (WIFSTOPPED(status))
        {
            // --- CASE 1: SYSCALL STOP ---
            // (SIGTRAP | 0x80) indicates a syscall because of PTRACE_O_TRACESYSGOOD
            if (WSTOPSIG(status) == (SIGTRAP | 0x80))
            {
                iov.iov_base = &regs;
                iov.iov_len = sizeof(regs);
                if (ptrace(PTRACE_GETREGSET, strace->pid, NT_PRSTATUS, &iov) == -1)
                    break;

                sys_arch = detect_sys_arch(&regs);
                
                // EXECVE FILTERING:
                // Do not print anything until the first specific execve call
                if (!is_print)
                {
                    unsigned long syscall_nr = regs.orig_rax;
                    // 59 = execve (x64), 11 = execve (i386)
                    if ((sys_arch == ARCH_X86_64 && syscall_nr == 59) || 
                        (sys_arch == ARCH_I386 && syscall_nr == 11))
                    {
                        is_print = 1;
                    }
                    else
                    {
                        // Skip this stop, but flip state to keep sync
                        is_entry = !is_entry; 
                        continue;
                    }
                }

                handle_syscall(strace, &regs, sys_arch, is_entry);
                is_entry = !is_entry;
            }
            // --- CASE 2: GENUINE SIGNAL ---
            // (SIGCHLD, SIGINT, SIGSEGV, etc.)
            else
            {
                ptrace(PTRACE_GETSIGINFO, strace->pid, 0, &si);

                // Do not print internal SIGTRAP (caused by PTRACE_ATTACH, etc.)
                if (si.si_signo != SIGTRAP)
                {
                    if (is_print || si.si_signo != SIGSTOP)
                    {
                        if (!strace->args.sum_opt)
                        {
                            fprintf(stderr, "--- %s ", sys_signame[si.si_signo]);
                            print_siginfo(&si);
                            fprintf(stderr, " ---\n");
                        }
                        
                        // SAVE THE SIGNAL to pass it back in the next ptrace call
                        sig = si.si_signo;
                    }
                }
            }
        }
    }

    // Handle final exit output
    if (!strace->args.sum_opt && !is_entry && is_print)
        fprintf(stderr, " = ?\n");

    if (strace->args.sum_opt)
        print_summary(strace);

    if (WIFSIGNALED(status))
    {
        if (!strace->args.sum_opt)
             fprintf(stderr, "+++ killed by %s +++\n", sys_signame[WTERMSIG(status)]);
        kill(getpid(), WTERMSIG(status));
    }
    else if (WIFEXITED(status))
    {
        if (!strace->args.sum_opt)
             fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
    }

    return WEXITSTATUS(status);
}