#include "strace.h"

const char args_doc[] = "[BINARY] ...";
const char doc[] = "";

static struct argp_option options[] = {
    {"summary-only", 'c', 0, 0, "Count time, calls, and errors for each system call"},
    {"help", '?', 0, 0, "give this help list"},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;

    switch (key)
    {
    case 'c':
        arguments->sum_opt = 1;
        break;
    case '?':
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
        return 0;
    case ARGP_KEY_NO_ARGS:
        argp_error(state, "must have PROG [ARGS]");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

int main(int ac, char **av, char **env)
{
    t_strace strace = {
        .args = {.target=NULL,.sum_opt=0}
    };
    
    // -- parse command line --
    int index;
    argp_parse(&argp, ac, av, 0, &index, &strace.args);
    ac -= index;
    av += index;

    strace.args.target = av;

    while (env[strace.n_env])
        strace.n_env++;

    strace.pid = fork();
    if (strace.pid < 0)
    {
        perror("vfork");
        return EXIT_FAILURE;
    }

    if(strace.pid == 0)
    {
        raise(SIGSTOP);
        // execvp(av[0], av);
        execlp(av[0], av[0], NULL);
        perror("exec");
    }

    return trace_bin(&strace);
}