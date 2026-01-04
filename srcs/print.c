#include "strace.h"
#include "signals.h"

/** SIG code mappings and print **/

const char *sys_signame[] = SYS_SIGNAME;

static const char *const sys_si_code[] = SI_CODE;
static const char *const ill_si_code[] = ILL_SI_CODE;
static const char *const fpe_si_code[] = FPE_SI_CODE;
static const char *const segv_si_code[] = SEGV_SI_CODE;
static const char *const bus_si_code[] = BUS_SI_CODE;
static const char *const trap_si_code[] = TRAP_SI_CODE;
static const char *const cld_si_code[] = CLD_SI_CODE;
static const char *const poll_si_code[] = POLL_SI_CODE;

static const char *safe_code(
    const char *const *tab, int code, size_t size)
{
    if (code >= 0 && (size_t)code < size && tab[code])
        return tab[code];
    return NULL;
}

typedef struct s_sigcode_map
{
    int signo;
    const char *const *codes;
    size_t size;
} t_sigcode_map;

static const t_sigcode_map sigcode_maps[] = {
    {SIGILL, ill_si_code, sizeof(ill_si_code) / sizeof(*ill_si_code)},
    {SIGFPE, fpe_si_code, sizeof(fpe_si_code) / sizeof(*fpe_si_code)},
    {SIGSEGV, segv_si_code, sizeof(segv_si_code) / sizeof(*segv_si_code)},
    {SIGBUS, bus_si_code, sizeof(bus_si_code) / sizeof(*bus_si_code)},
    {SIGTRAP, trap_si_code, sizeof(trap_si_code) / sizeof(*trap_si_code)},
    {SIGCHLD, cld_si_code, sizeof(cld_si_code) / sizeof(*cld_si_code)},
    {SIGPOLL, poll_si_code, sizeof(poll_si_code) / sizeof(*poll_si_code)},
};

void print_siginfo(siginfo_t *si)
{
    const char *code = NULL;

    /* Signal-specific si_code */
    for (size_t i = 0; i < sizeof(sigcode_maps) / sizeof(*sigcode_maps); i++)
    {
        if (si->si_signo == sigcode_maps[i].signo)
        {
            code = safe_code(
                sigcode_maps[i].codes,
                si->si_code,
                sigcode_maps[i].size);
            break;
        }
    }

    /* Generic SI_* codes */
    if (!code)
    {
        switch (si->si_code)
        {
        case SI_USER:
            code = sys_si_code[1];
            break;
        case SI_KERNEL:
            code = sys_si_code[2];
            break;
        case SI_QUEUE:
            code = sys_si_code[3];
            break;
        case SI_TIMER:
            code = sys_si_code[4];
            break;
        case SI_MESGQ:
            code = sys_si_code[5];
            break;
        case SI_ASYNCIO:
            code = sys_si_code[6];
            break;
        case SI_SIGIO:
            code = sys_si_code[7];
            break;
        case SI_TKILL:
            code = sys_si_code[8];
            break;
        default:
            code = sys_si_code[0];
            break;
        }
    }

    fprintf(stderr,
            "{si_signo=%s, si_code=%s, si_addr=%p}",
            sys_signame[si->si_signo],
            code,
            si->si_addr);
}

/** print functions **/

void put_escaped_char(uint8_t c)
{
    if (c == '\n')
        fprintf(stderr, "\\n");
    else if (c == '\t')
        fprintf(stderr, "\\t");
    else if (c == '\r')
        fprintf(stderr, "\\r");
    else if (c == '\"')
        fprintf(stderr, "\\\"");
    else if (c >= 32 && c <= 126)
        fputc(c, stderr);
    else
        fprintf(stderr, "\\%03o", c); // Octal is standard for strace
}

void print_argv(char **argv)
{
    fprintf(stderr, "[");
    for (int i = 0; argv && argv[i]; i++)
    {
        fprintf(stderr, "%s\"%s\"", i > 0 ? ", " : "", argv[i]);
    }
    fprintf(stderr, "]");
}

void print_string(pid_t pid, void *addr)
{
    if (!addr)
    {
        fprintf(stderr, "NULL");
        return;
    }

    uint8_t buf[48]; // Only read what we might actually print
    struct iovec local = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct iovec remote = {.iov_base = addr, .iov_len = sizeof(buf)};

    ssize_t nread = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (nread <= 0)
    {
        fprintf(stderr, "%p", addr);
        return;
    }

    fprintf(stderr, "\"");
    for (int i = 0; i < nread; i++)
    {
        if (buf[i] == '\0')
            break;
        if (i == 32)
        { // Truncate long strings like strace
            fprintf(stderr, "\"...");
            return;
        }
        put_escaped_char(buf[i]);
    }
    fprintf(stderr, "\"");
}

void print_flag_open(int flags)
{
    struct
    {
        int val;
        char *name;
    } table[] = {
        {O_APPEND, "O_APPEND"}, {O_ASYNC, "O_ASYNC"}, {O_CLOEXEC, "O_CLOEXEC"}, {O_CREAT, "O_CREAT"}, {O_DIRECT, "O_DIRECT"}, {O_DIRECTORY, "O_DIRECTORY"}, {O_EXCL, "O_EXCL"}, {O_NOATIME, "O_NOATIME"}, {O_NOFOLLOW, "O_NOFOLLOW"}, {O_NONBLOCK, "O_NONBLOCK"}, {O_TRUNC, "O_TRUNC"}, {0, NULL}};

    // Handle Access Mode (First 2 bits usually)
    int acc = flags & O_ACCMODE;
    fprintf(stderr, acc == O_RDONLY ? "O_RDONLY" : acc == O_WRONLY ? "O_WRONLY"
                                                                   : "O_RDWR");

    // Handle Bit Flags
    for (int i = 0; table[i].name; i++)
    {
        if (flags & table[i].val)
            fprintf(stderr, "|%s", table[i].name);
    }
}

void print_syscall(t_strace *strace, syscall_t sc, int argc, ...)
{
    va_list ap;
    va_start(ap, argc);

    fprintf(stderr, "%s(", sc.name);
    for (int i = 0; i < argc; i++)
    {
        if (i > 0)
            fprintf(stderr, ", ");

        long arg = va_arg(ap, long); // Get raw value, cast based on type
        switch (sc.type_args[i])
        {
        case INT:
            fprintf(stderr, "%d", (int)arg);
            break;
        case ULONG:
            fprintf(stderr, "%lu", (unsigned long)arg);
            break;
        case PTR:
            arg ? fprintf(stderr, "%p", (void *)arg) : fprintf(stderr, "NULL");
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