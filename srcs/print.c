#include "strace.h"
#include "signals.h"

const char *sys_signame[] = SYS_SIGNAME;

static const char *const sys_si_code[] = SI_CODE;
static const char *const ill_si_code[] = ILL_SI_CODE;
static const char *const fpe_si_code[] = FPE_SI_CODE;
static const char *const segv_si_code[] = SEGV_SI_CODE;
static const char *const bus_si_code[] = BUS_SI_CODE;
static const char *const trap_si_code[] = TRAP_SI_CODE;
static const char *const cld_si_code[] = CLD_SI_CODE;
static const char *const poll_si_code[] = POLL_SI_CODE;

typedef struct
{
    int signo;
    const char *const *codes;
    size_t size;
} t_sigcode_map;

static const t_sigcode_map sigcode_maps[] = {
    {SIGILL, ill_si_code, sizeof(ill_si_code) / sizeof(char *)},
    {SIGFPE, fpe_si_code, sizeof(fpe_si_code) / sizeof(char *)},
    {SIGSEGV, segv_si_code, sizeof(segv_si_code) / sizeof(char *)},
    {SIGBUS, bus_si_code, sizeof(bus_si_code) / sizeof(char *)},
    {SIGTRAP, trap_si_code, sizeof(trap_si_code) / sizeof(char *)},
    {SIGCHLD, cld_si_code, sizeof(cld_si_code) / sizeof(char *)},
    {SIGPOLL, poll_si_code, sizeof(poll_si_code) / sizeof(char *)},
};

/**
 * @brief Print siginfo_t structure details
 * @param si
 */
void print_siginfo(siginfo_t *si)
{
    const char *code = NULL;

    // specific signal codes
    for (size_t i = 0; i < sizeof(sigcode_maps) / sizeof(t_sigcode_map); i++)
    {
        if (si->si_signo == sigcode_maps[i].signo)
        {
            if (si->si_code >= 0 && (size_t)si->si_code < sigcode_maps[i].size)
                code = sigcode_maps[i].codes[si->si_code];
            break;
        }
    }

    // generic codes
    if (!code)
    {
        static const struct
        {
            int code;
            int idx;
        } generic_map[] = {
            {SI_USER, 1}, {SI_KERNEL, 2}, {SI_QUEUE, 3}, {SI_TIMER, 4}, {SI_MESGQ, 5}, {SI_ASYNCIO, 6}, {SI_SIGIO, 7}, {SI_TKILL, 8}};
        code = sys_si_code[0]; // Default
        for (size_t i = 0; i < 8; i++)
        {
            if (si->si_code == generic_map[i].code)
            {
                code = sys_si_code[generic_map[i].idx];
                break;
            }
        }
    }

    fprintf(stderr, "{si_signo=%s, si_code=%s, si_addr=%p}",
            sys_signame[si->si_signo], code, si->si_addr);
}

/**
 * @brief Print a single character with escaping
 * @param c
 */
void put_escaped_char(uint8_t c)
{
    switch (c)
    {
    case '\n':
        fprintf(stderr, "\\n");
        break;
    case '\t':
        fprintf(stderr, "\\t");
        break;
    case '\r':
        fprintf(stderr, "\\r");
        break;
    case '\"':
        fprintf(stderr, "\\\"");
        break;
    default:
        if (c >= 32 && c <= 126)
            fputc(c, stderr);
        else
            fprintf(stderr, "\\%03o", c);
    }
}

/**
 * @brief Print a NULL-terminated array of strings
 * @param argv
 */
void print_argv(char **argv)
{
    fprintf(stderr, "[");
    for (int i = 0; argv && argv[i]; i++)
        fprintf(stderr, "%s\"%s\"", i ? ", " : "", argv[i]);
    fprintf(stderr, "]");
}

/**
 * @brief Print a string from the process memory
 * @param pid
 * @param addr
 */
void print_string(pid_t pid, void *addr)
{
    uint8_t buf[48];
    struct iovec local = {buf, sizeof(buf)}, remote = {addr, sizeof(buf)};

    if (!addr)
    {
        fprintf(stderr, "NULL");
        return;
    }

    ssize_t nread = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (nread <= 0)
    {
        fprintf(stderr, "%p", addr);
        return;
    }

    fprintf(stderr, "\"");
    for (int i = 0; i < nread && buf[i]; i++)
    {
        if (i == 32)
        {
            fprintf(stderr, "\"...");
            return;
        }
        put_escaped_char(buf[i]);
    }
    fprintf(stderr, "\"");
}

/**
 * @brief Print open flags in symbolic form
 * @param flags
 */
void print_flag_open(int flags)
{
    static const struct
    {
        int val;
        char *name;
    } flags_map[] = {
        {O_APPEND, "O_APPEND"}, {O_ASYNC, "O_ASYNC"}, {O_CLOEXEC, "O_CLOEXEC"}, \
        {O_CREAT, "O_CREAT"}, {O_DIRECT, "O_DIRECT"}, {O_DIRECTORY, "O_DIRECTORY"}, \
        {O_EXCL, "O_EXCL"}, {O_NOATIME, "O_NOATIME"}, {O_NOFOLLOW, "O_NOFOLLOW"}, \
        {O_NONBLOCK, "O_NONBLOCK"}, {O_TRUNC, "O_TRUNC"}, {0, NULL}};

    int acc = flags & O_ACCMODE;
    fprintf(stderr, acc == O_RDONLY ? "O_RDONLY" : acc == O_WRONLY ? "O_WRONLY"
                                                                   : "O_RDWR");

    for (int i = 0; flags_map[i].name; i++)
        if (flags & flags_map[i].val)
            fprintf(stderr, "|%s", flags_map[i].name);
}

/**
 * @brief Print a system call and its arguments
 * @param strace
 * @param sc
 * @param argc
 */
void print_syscall(t_strace *strace, syscall_t sc, int argc, ...)
{
    va_list ap;
    va_start(ap, argc);

    fprintf(stderr, "%s(", sc.name);
    for (int i = 0; i < argc; i++)
    {
        if (i > 0)
            fprintf(stderr, ", ");
        long arg = va_arg(ap, long);

        switch (sc.type_args[i])
        {
        case INT:
            fprintf(stderr, "%d", (int)arg);
            break;
        case ULONG:
            fprintf(stderr, "%lu", (unsigned long)arg);
            break;
        case PTR:
            fprintf(stderr, arg ? "%p" : "NULL", (void *)arg);
            break;
        case STR:
            print_string(strace->pid, (void *)arg);
            break;
        case ARGV:
            print_argv((char **)arg);
            break;
        case FLAG_OPEN:
            print_flag_open((int)arg);
            break;
        case ENVP:
            fprintf(stderr, "%p /* %ld vars */", (void *)arg, strace->n_env);
            break;
        case SIGNAL:
            if (arg < SYS_SIGNAME_COUNT)
                fprintf(stderr, "%s", sys_signame[arg]);
            else
                fprintf(stderr, "%ld", arg);
            break;
        default:
            fprintf(stderr, "%#lx", arg);
            break;
        }
    }
    va_end(ap);
    fprintf(stderr, ")");
}