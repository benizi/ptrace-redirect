#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>

/* Default to no debug printf's */
#ifndef DEBUG
# define DEBUG 0
#endif

/* Categories for debug printf's: */
#define DBG_NAME (1 << 0)
#define DBG_WAIT (1 << 1)

static void process_signals(pid_t child);
static int wait_for_open(pid_t child);
static void read_file(pid_t child, char *file, int reg);
static void redirect_file(pid_t child, const char *file, int reg);

int main(int argc, char **argv)
{
    pid_t pid;
    int status;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <prog> <arg1> ... <argN>\n", argv[0]);
        return 1;
    }

    if ((pid = fork()) == 0) {
        /* If syscall is open or openat, trace, otherwise allow it through */
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 2, 0),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 1, 0),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),
        };
        struct sock_fprog prog = {
            .filter = filter,
            .len = (unsigned short) (sizeof(filter)/sizeof(filter[0])),
        };
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        /* To avoid the need for CAP_SYS_ADMIN */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            return 1;
        }
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
            perror("when setting seccomp filter");
            return 1;
        }
        kill(getpid(), SIGSTOP);
        return execvp(argv[1], argv + 1);
    } else {
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);
        process_signals(pid);
        return 0;
    }
}

static void process_signals(pid_t child)
{
    const char *file_to_redirect = "ONE.txt";
    const char *file_to_avoid = "TWO.txt";
    int reg;

    while(1) {
        char orig_file[PATH_MAX];

        /* Wait for open/openat syscall start */
        reg = wait_for_open(child);
        if (!reg) break;

        /* Find out file and re-direct if it is the target */

        read_file(child, orig_file, reg);
        if (DEBUG & DBG_NAME) printf("[Opening %s]\n", orig_file);

        if (strcmp(file_to_avoid, orig_file) == 0)
            redirect_file(child, file_to_redirect, reg);
    }
}

static int wait_for_open(pid_t child)
{
    int status;

    while (1) {
        ptrace(PTRACE_CONT, child, 0, 0);
        waitpid(child, &status, 0);
        if (DEBUG & DBG_WAIT) printf("[waitpid status: 0x%08x]\n", status);
        /* Is it our filter for the open/openat syscall? */
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
            switch (ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX, 0)) {
                /* open(char*, ...) - in %rdi */
                case __NR_open: return RDI;
                /* openat(int, char*, ...) - in %rsi */
                case __NR_openat: return RSI;
            }
        }
        if (WIFEXITED(status))
            return 0;
    }
}

static void read_file(pid_t child, char *file, int reg)
{
    char *child_addr;
    int i;

    child_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long)*reg, 0);

    do {
        long val;
        char *p;

        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
        if (val == -1) {
            fprintf(stderr, "PTRACE_PEEKTEXT error: %s", strerror(errno));
            exit(1);
        }
        child_addr += sizeof (long);

        p = (char *) &val;
        for (i = 0; i < sizeof (long); ++i, ++file) {
            *file = *p++;
            if (*file == '\0') break;
        }
    } while (i == sizeof (long));
}

static void redirect_file(pid_t child, const char *file, int reg)
{
    char *stack_addr, *file_addr;

    stack_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RSP, 0);
    /* Move further of red zone and make sure we have space for the file name */
    stack_addr -= 128 + PATH_MAX;
    file_addr = stack_addr;

    /* Write new file in lower part of the stack */
    do {
        int i;
        char val[sizeof (long)];

        for (i = 0; i < sizeof (long); ++i, ++file) {
            val[i] = *file;
            if (*file == '\0') break;
        }

        ptrace(PTRACE_POKETEXT, child, stack_addr, *(long *) val);
        stack_addr += sizeof (long);
    } while (*file);

    /* Change argument to open */
    ptrace(PTRACE_POKEUSER, child, sizeof(long)*reg, file_addr);
}
