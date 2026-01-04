#ifndef SIGNALS_H
# define SIGNALS_H

# define SYS_SIGNAME_COUNT 33

# define SYS_SIGNAME { \
	[0] = NULL, \
	[1] = "SIGHUP", \
	[2] = "SIGINT", \
	[3] = "SIGQUIT", \
	[4] = "SIGILL", \
	[5] = "SIGTRAP", \
	[6] = "SIGABRT", \
	[7] = "SIGBUS", \
	[8] = "SIGFPE", \
	[9] = "SIGKILL", \
	[10] = "SIGUSR1", \
	[11] = "SIGSEGV", \
	[12] = "SIGUSR2", \
	[13] = "SIGPIPE", \
	[14] = "SIGALRM", \
	[15] = "SIGTERM", \
	[16] = "SIGSTKFLT", \
	[17] = "SIGCHLD", \
	[18] = "SIGCONT", \
	[19] = "SIGSTOP", \
	[20] = "SIGTSTP", \
	[21] = "SIGTTIN", \
	[22] = "SIGTTOU", \
	[23] = "SIGURG", \
	[24] = "SIGXCPU", \
	[25] = "SIGXFSZ", \
	[26] = "SIGVTALRM", \
	[27] = "SIGPROF", \
	[28] = "SIGWINCH", \
	[29] = "SIGIO", \
	[30] = "SIGPWR", \
	[31] = "SIGSYS", \
	[32] = "SIGRTMIN" \
}

# define SI_CODE { \
	[0] = "", \
	[1] = "SI_USER", \
	[2] = "SI_KERNEL", \
	[3] = "SI_QUEUE", \
	[4] = "SI_TIMER", \
	[5] = "SI_MESGQ", \
	[6] = "SI_ASYNCIO", \
	[7] = "SI_SIGIO", \
	[8] = "SI_TKILL" \
}

# define ILL_SI_CODE { \
	[ILL_ILLOPC] = "ILL_ILLOPC", \
	[ILL_ILLOPN] = "ILL_ILLOPN", \
	[ILL_ILLADR] = "ILL_ILLADR", \
	[ILL_ILLTRP] = "ILL_ILLTRP", \
	[ILL_PRVOPC] = "ILL_PRVOPC", \
	[ILL_PRVREG] = "ILL_PRVREG", \
	[ILL_COPROC] = "ILL_COPROC", \
	[ILL_BADSTK] = "ILL_BADSTK" \
}

# define FPE_SI_CODE { \
	[FPE_INTDIV] = "FPE_INTDIV", \
	[FPE_INTOVF] = "FPE_INTOVF", \
	[FPE_FLTDIV] = "FPE_FLTDIV", \
	[FPE_FLTOVF] = "FPE_FLTOVF", \
	[FPE_FLTUND] = "FPE_FLTUND", \
	[FPE_FLTRES] = "FPE_FLTRES", \
	[FPE_FLTINV] = "FPE_FLTINV", \
	[FPE_FLTSUB] = "FPE_FLTSUB" \
}

# define SEGV_SI_CODE { \
	[SEGV_MAPERR] = "SEGV_MAPERR", \
    [SEGV_ACCERR] = "SEGV_ACCERR" \
}

# define BUS_SI_CODE { \
	[BUS_ADRALN] = "BUS_ADRALN", \
	[BUS_ADRERR] = "BUS_ADRERR", \
	[BUS_OBJERR] = "BUS_OBJERR" \
}

# define TRAP_SI_CODE { \
	[TRAP_BRKPT] = "TRAP_BRKPT", \
	[TRAP_TRACE] = "TRAP_TRACE" \
}

# define CLD_SI_CODE { \
	[CLD_EXITED] = "CLD_EXITED", \
	[CLD_KILLED] = "CLD_KILLED", \
	[CLD_DUMPED] = "CLD_DUMPED", \
	[CLD_TRAPPED] = "CLD_TRAPPED", \
	[CLD_STOPPED] = "CLD_STOPPED", \
	[CLD_CONTINUED] = "CLD_CONTINUED" \
}

# define POLL_SI_CODE { \
	[POLL_IN] = "POLL_IN", \
	[POLL_OUT] = "POLL_OUT", \
	[POLL_MSG] = "POLL_MSG", \
	[POLL_ERR] = "POLL_ERR", \
	[POLL_PRI] = "POLL_PRI", \
	[POLL_HUP] = "POLL_HUP" \
}

#endif