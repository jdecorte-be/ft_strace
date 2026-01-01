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
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

int main(int ac, char **av)
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



    strace.child = fork();
    if(strace.child == 0)
        return exec_bin(ac, av);
    else
        return trace_bin(&strace);
}