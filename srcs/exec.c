#include "strace.h"

static char *find_in_path(const char *cmd)
{
    char *path_env = getenv("PATH");
    if (!path_env)
        return NULL;

    char *path = strdup(path_env);
    if (!path)
        return NULL;

    char *path_copy = path;
    char *dir = strtok(path, ":");
    char *full_path = NULL;

    while (dir)
    {
        size_t len = strlen(dir) + strlen(cmd) + 2;
        full_path = malloc(len);
        if (!full_path)
        {
            free(path_copy);
            return NULL;
        }

        snprintf(full_path, len, "%s/%s", dir, cmd);
        
        if (access(full_path, X_OK) == 0)
        {
            free(path_copy);
            return full_path;
        }

        free(full_path);
        full_path = NULL;
        dir = strtok(NULL, ":");
    }

    free(path_copy);
    return NULL;
}

void exec_with_path(char **av, char **env)
{
    execve(av[0], av, env);
    
    if (errno == ENOENT && strchr(av[0], '/') == NULL)
    {
        char *full_path = find_in_path(av[0]);
        if (full_path)
        {
            execve(full_path, av, env);
            free(full_path);
        }
    }
    
    fprintf(stderr, "%s: %s\n", av[0], strerror(errno));
    exit(EXIT_FAILURE);
}
