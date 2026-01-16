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
t_sys_arch detect_sys_arch(struct iovec *iov)
{
    if (sizeof(struct user_regs_struct) == iov->iov_len)
        return ARCH_X86_64;
    else if (sizeof(struct i386_user_regs_struct) == iov->iov_len)
        return ARCH_I386;
    else
        error(EXIT_FAILURE, 0, "Unknown architecture detected");
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

static void update_summary(t_strace *strace, void *regs, const syscall_t *table, unsigned long syscall_num, t_sys_arch arch, _Bool is_entry)
{
    t_stats *stats = (arch == ARCH_X86_64) ? &strace->stats_64[syscall_num] : &strace->stats_32[syscall_num];
    long long ret;

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

        if (arch == ARCH_X86_64)
            ret = (long long)((struct user_regs_struct *)regs)->rax;
        else
            ret = (long long)((struct i386_user_regs_struct *)regs)->eax;

        if (ret > -4096 && ret < 0)
            stats->errors++;
    }
}

static void handle_x86_64_syscall(t_strace *strace, struct user_regs_struct *regs, _Bool is_entry)
{
    if (strace->args.sum_opt)
        return update_summary(strace, regs, x86_64_syscall, regs->orig_rax, ARCH_X86_64, is_entry);

    if (regs->rax == -ENOSYS && regs->orig_rax < MAX_X86_64_SYSCALL)
    {
        print_syscall(strace, x86_64_syscall[regs->orig_rax], x86_64_syscall[regs->orig_rax].argc,
                      (uint32_t)regs->rdi, (uint32_t)regs->rsi, (uint32_t)regs->rdx,
                      (uint32_t)regs->r10, (uint32_t)regs->r8, (uint32_t)regs->r9);
    }
    else
    {
        if (x86_64_syscall[regs->orig_rax].type_ret == INT)
            fprintf(stderr, " = %d\n", (int)regs->rax);
        else
            fprintf(stderr, " = %#lx\n", regs->rax);
    }

}

static void handle_i386_syscall(t_strace *strace, struct i386_user_regs_struct *regs, _Bool is_entry)
{
    if (strace->args.sum_opt)
        return update_summary(strace, regs, i386_syscall, regs->orig_eax, ARCH_I386, is_entry);

    if (regs->eax == -ENOSYS && regs->orig_eax < MAX_I386_SYSCALL)
    {
        print_syscall(strace, i386_syscall[regs->orig_eax], i386_syscall[regs->orig_eax].argc,
                      (uint32_t)regs->ebx, (uint32_t)regs->ecx, (uint32_t)regs->edx,
                      (uint32_t)regs->esi, (uint32_t)regs->edi, (uint32_t)regs->ebp);
    }
    else
    {
        if (i386_syscall[regs->orig_eax].type_ret == INT)
            fprintf(stderr, " = %d\n", (int)regs->eax);
        else
            fprintf(stderr, " = %#x\n", regs->eax);
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
	union {
		struct user_regs_struct x86_64_r;
		struct i386_user_regs_struct i386_r;
	}	regs;

    int status;
    int sig = 0;
    struct iovec iov;
    siginfo_t si;
    t_sys_arch sys_arch;

    _Bool is_entry = 1;
    _Bool is_started = 0;

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

        sig = 0;
        
        if (waitpid(strace->pid, &status, 0) < 0)
            break;

        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;

        if (WIFSTOPPED(status) && WSTOPSIG(status) != (SIGTRAP | 0x80))
        {
            sig = WSTOPSIG(status);

            if (sig == SIGINT) 
                return EXIT_SUCCESS;

            ptrace(PTRACE_GETSIGINFO, strace->pid, 0, &si);

            if (sig != SIGTRAP && sig != SIGSTOP)
            {
                if (is_started && !strace->args.sum_opt)
                {
                    fprintf(stderr, "--- %s ", sys_signame[sig]);
                    print_siginfo(&si);
                    fprintf(stderr, " ---\n");
                }
            }
            else
                sig = 0;

            continue;
        }

        if (WIFSTOPPED(status))
        {
            iov.iov_base = &regs;
            iov.iov_len = sizeof(regs);

            if (ptrace(PTRACE_GETREGSET, strace->pid, NT_PRSTATUS, &iov) < 0)
                break;

            sys_arch = detect_sys_arch(&iov);
            
            // execve filtering
            if (!is_started)
            {
                unsigned long syscall_nr = (sys_arch == ARCH_X86_64) ? regs.x86_64_r.orig_rax : regs.i386_r.orig_eax;

                // 59 = execve (x64), 11 = execve (i386)
                if ((sys_arch == ARCH_X86_64 && syscall_nr == 59) || 
                    (sys_arch == ARCH_I386 && syscall_nr == 11))
                {
                    if (is_entry)
                    {
                        if (strace->args.sum_opt)
                            update_summary(strace, &regs, (sys_arch == ARCH_X86_64) ? x86_64_syscall : i386_syscall, syscall_nr, sys_arch, is_entry);

                        snprintf(strace->execve_buffer, sizeof(strace->execve_buffer), 
                        "execve(\"%s\", [/* arguments */], [/* %ld vars */])", 
                        "NULL", strace->n_env);
                    }
                    else
                    {
                        long ret = (sys_arch == ARCH_X86_64) ? (long)regs.x86_64_r.rax : (long)regs.i386_r.eax;
                        if (ret == 0)
                        {
                            is_started = 1;
                            if (!strace->args.sum_opt)
                                fprintf(stderr, "%s = 0\n", strace->execve_buffer);
                        }
                    }
                }
                else
                {
                    is_entry = !is_entry; 
                    continue;
                }
            }
            else
            {
                if (sys_arch == ARCH_X86_64)
                    handle_x86_64_syscall(strace, &regs.x86_64_r, is_entry);
                else if (sys_arch == ARCH_I386)
                    handle_i386_syscall(strace, &regs.i386_r, is_entry);
            }
            

            is_entry = !is_entry;
 
        }
    }

    if (!is_started)
        return EXIT_FAILURE;

    if (!strace->args.sum_opt && !is_entry)
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