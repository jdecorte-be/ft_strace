#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    kill(getpid(), SIGSEGV);
    return 0;
}
