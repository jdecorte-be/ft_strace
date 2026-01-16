#include "strace.h"

/**
 * @brief Compare two statistics entries for sorting
 *
 * @param a
 * @param b
 * @return int
 */
static int compare_stats(const void *a, const void *b)
{
    const t_stats *sa = *(const t_stats **)a;
    const t_stats *sb = *(const t_stats **)b;

    if (sa->total_time.tv_sec > sb->total_time.tv_sec)
        return -1;
    if (sa->total_time.tv_sec < sb->total_time.tv_sec)
        return 1;
    if (sa->total_time.tv_nsec > sb->total_time.tv_nsec)
        return -1;
    if (sa->total_time.tv_nsec < sb->total_time.tv_nsec)
        return 1;
    return 0;
}

/**
 * @brief Print the summary of gathered syscall statistics
 *
 * @param strace
 */
void print_summary(t_strace *strace)
{
    t_stats *ptrs[MAX_X86_64_SYSCALL + MAX_I386_SYSCALL];
    int count = 0;

    for (int i = 0; i < MAX_X86_64_SYSCALL; i++)
    {
        if (strace->stats_64[i].calls > 0)
            ptrs[count++] = &strace->stats_64[i];
    }
    for (int i = 0; i < MAX_I386_SYSCALL; i++)
    {
        if (strace->stats_32[i].calls > 0)
            ptrs[count++] = &strace->stats_32[i];
    }

    qsort(ptrs, count, sizeof(t_stats *), compare_stats);

    // calc totals
    struct timespec total_all = {0, 0};
    unsigned long long total_calls = 0;
    unsigned long long total_errors = 0;

    for (int i = 0; i < count; i++)
    {
        total_calls += ptrs[i]->calls;
        total_errors += ptrs[i]->errors;
        total_all.tv_sec += ptrs[i]->total_time.tv_sec;
        total_all.tv_nsec += ptrs[i]->total_time.tv_nsec;
        if (total_all.tv_nsec >= 1000000000)
        {
            total_all.tv_sec++;
            total_all.tv_nsec -= 1000000000;
        }
    }

    double total_seconds = total_all.tv_sec + total_all.tv_nsec / 1000000000.0;

    fprintf(stderr, "%6s %11s %11s %9s %9s %s\n",
            "% time", "seconds", "usecs/call", "calls", "errors", "syscall");
    fprintf(stderr, "%6s %11s %11s %9s %9s %s\n",
            "------", "-----------", "-----------", "---------", "---------", "----------------");

    for (int i = 0; i < count; i++)
    {
        double s_seconds = ptrs[i]->total_time.tv_sec + ptrs[i]->total_time.tv_nsec / 1000000000.0;
        double usecs_call = (s_seconds * 1000000.0) / ptrs[i]->calls;
        double percent = (total_seconds > 0) ? (s_seconds / total_seconds * 100.0) : 0.0;

        fprintf(stderr, "%6.2f %11.6f %11.0f %9llu %9llu %s\n",
                percent, s_seconds, usecs_call, ptrs[i]->calls, ptrs[i]->errors, ptrs[i]->name ? ptrs[i]->name : "unknown");
    }

    fprintf(stderr, "%6s %11s %11s %9s %9s %s\n",
            "------", "-----------", "-----------", "---------", "---------", "----------------");

    fprintf(stderr, "%6.2f %11.6f %11s %9llu %9llu %s\n",
            100.00, total_seconds, "", total_calls, total_errors, "total");
}