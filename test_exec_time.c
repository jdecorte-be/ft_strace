#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <sys/wait.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc > 1) {
        // Child (after execve)
        struct timespec ts;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
        printf("After execve: %ld.%09ld\n", ts.tv_sec, ts.tv_nsec);
        return 0;
    }

    // Parent
    pid_t pid = fork();
    if (pid == 0) {
        // Child
        struct timespec ts;
        // Burn some CPU
        for(volatile int i=0; i<10000000; i++);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
        printf("Before execve: %ld.%09ld\n", ts.tv_sec, ts.tv_nsec);
        
        char *args[] = {argv[0], "child", NULL};
        execv(argv[0], args);
        perror("execv");
        exit(1);
    }
    wait(NULL);
    return 0;
}
