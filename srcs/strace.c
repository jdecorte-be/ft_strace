#include "strace.h"
#include "syscalls.h"

/* Global tables */
const syscall_t			x86_64_syscall[] = X86_64_SYSCALL;
const syscall_t			i386_syscall[] = I386_SYSCALL;
extern const char		*sys_signame[];

/**
 * @brief Detect the architecture (x86_64 or i386) based on code segment register
 *
 * @param regs
 * @return t_sys_arch
 */
t_sys_arch detect_sys_arch(struct user_regs_struct *regs)
{
    if (regs->cs == 0x33)
        return ARCH_X86_64;
    else if (regs->cs == 0x23)
        return ARCH_I386;
    else
        return ARCH_UNKNOWN;
}

/**
 * @brief Retrieve the current time for syscall duration measurement
 *
 * @param pid
 * @param ts
 */
static void get_time(pid_t pid, struct timespec *ts)
{
    clockid_t cid;
    if (clock_getcpuclockid(pid, &cid) != 0 || clock_gettime(cid, ts) != 0)
        clock_gettime(CLOCK_MONOTONIC, ts);
}

/**
 * @brief Block standard termination signals during tracing
 *
 * @param pid
 */
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


/**
 * @brief Handle system call entry and exit events
 *
 * Dispatches logic based on architecture, maps registers to arguments,
 * updates statistics if summary mode is active, or prints formatted
 * syscall arguments and return values to stderr.
 *
 * @param strace
 * @param regs
 * @param arch
 * @param is_entry
 */
void handle_syscall(t_strace *strace, struct user_regs_struct *regs, t_sys_arch arch, _Bool is_entry)
{
    const syscall_t *table;
    unsigned long syscall_num = regs->orig_rax;
    unsigned long max_syscall;
    unsigned long args[6];
    
    if (arch == ARCH_X86_64)
    {
        table = x86_64_syscall;
        max_syscall = MAX_X86_64_SYSCALL;
        
        args[0] = regs->rdi; args[1] = regs->rsi; args[2] = regs->rdx;
        args[3] = regs->r10; args[4] = regs->r8;  args[5] = regs->r9;
    }
    else if (arch == ARCH_I386)
    {
        table = i386_syscall;
        max_syscall = MAX_I386_SYSCALL;
        
        args[0] = (uint32_t)regs->rbx; args[1] = (uint32_t)regs->rcx; args[2] = (uint32_t)regs->rdx;
        args[3] = (uint32_t)regs->rsi; args[4] = (uint32_t)regs->rdi; args[5] = (uint32_t)regs->rbp;
    }
    else
        error(EXIT_FAILURE, 0, "Unknown architecture detected");

    if (syscall_num >= max_syscall)
        return; 

    if (strace->args.sum_opt)
    {
        t_stats *stats = (arch == ARCH_X86_64) ? &strace->stats_64[syscall_num] : &strace->stats_32[syscall_num];
        
        if (is_entry)
        {
            get_time(strace->pid, &strace->start_ts);
            stats->calls++;
            stats->name = table[syscall_num].name;
        }
        else
        {
            struct timespec end_ts, diff;
            get_time(strace->pid, &end_ts);
            
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

        // linux kernel errors are -1 to -4095
        if (ret > -4096 && ret < 0)
            fprintf(stderr, " = -1 E%lld (%s)\n", -ret, strerror(-ret));
        else
        {
            if (table[syscall_num].type_ret == INT)
            {
                if (arch == ARCH_I386)
                    fprintf(stderr, " = %d\n", (int)regs->rax);
                else
                    fprintf(stderr, " = %d\n", (int)regs->rax);
            }
            else
            {
                if (arch == ARCH_I386)
                    fprintf(stderr, " = %#x\n", (unsigned int)regs->rax);
                else
                    fprintf(stderr, " = %#lx\n", regs->rax);
            }
        }
    }
}


/**
 * @brief Main tracing loop responsible for attaching and monitoring the process
 *
 * @param strace
 * @return int
 */
int trace_bin(t_strace *strace)
{
    int status;
    int sig = 0;
    struct user_regs_struct regs;
    struct iovec iov;
    siginfo_t si;
    t_sys_arch sys_arch;

    _Bool is_entry = 1;
    _Bool is_print = 0;

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
        if (ptrace(PTRACE_SYSCALL, strace->pid, 0, sig) < 0)
            break;
        
        if (waitpid(strace->pid, &status, 0) < 0)
            break;

        sig = 0;

        // exited or was killed by signal
        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;

        // check if stopped
        if (WIFSTOPPED(status))
        {
            // --- case 1: syscall stop ---
            if (WSTOPSIG(status) == (SIGTRAP | 0x80))
            {
                iov.iov_base = &regs;
                iov.iov_len = sizeof(regs);
                if (ptrace(PTRACE_GETREGSET, strace->pid, NT_PRSTATUS, &iov) == -1)
                    break;

                sys_arch = detect_sys_arch(&regs);
                
                // execve filtering
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
                        is_entry = !is_entry; 
                        continue;
                    }
                }

                handle_syscall(strace, &regs, sys_arch, is_entry);
                is_entry = !is_entry;
            }
            // --- case 2: others signal ---
            else
            {
                ptrace(PTRACE_GETSIGINFO, strace->pid, 0, &si);

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
                        
                        sig = si.si_signo;
                    }
                }
            }
        }
    }

    // final exit handling --
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