#include <gtest/gtest.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "block-anogs.hpp"

// All of these helpers permanently alter the calling process (seccomp jail,
// ptrace state, rlimits), so each one runs in a forked child and the parent
// inspects the exit status.

TEST(InstallSeccompFilter, BlocksFileOpenSyscalls) {
    pid_t pid = fork();
    ASSERT_GE(pid, 0);

    if (pid == 0) {
        installSeccompFilter();

        // open()/openat() are blocked and must fail with EPERM, not succeed.
        int fd = open("/etc/hostname", O_RDONLY);
        if (fd >= 0) {
            close(fd);
            _exit(1);
        }
        _exit(errno == EPERM ? 0 : 2);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status)) << "child terminated abnormally";
    EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(InstallSeccompFilter, AllowsWriteSyscall) {
    pid_t pid = fork();
    ASSERT_GE(pid, 0);

    if (pid == 0) {
        installSeccompFilter();
        // write() is not in the blocklist and must keep working.
        ssize_t n = write(STDERR_FILENO, "", 0);
        _exit(n == 0 ? 0 : 1);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(PreventPtrace, SucceedsForUntracedProcess) {
    pid_t pid = fork();
    ASSERT_GE(pid, 0);

    if (pid == 0) {
        // An untraced child can set PTRACE_TRACEME, so preventPtrace() must
        // return normally rather than _exit(-1).
        preventPtrace();
        _exit(0);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status)) << "preventPtrace exited the process";
    EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(SetupAntiDebug, CompletesAndDisablesCoreDumps) {
    pid_t pid = fork();
    ASSERT_GE(pid, 0);

    if (pid == 0) {
        setupAntiDebug();

        struct rlimit rl;
        if (getrlimit(RLIMIT_CORE, &rl) != 0) _exit(2);
        // setupAntiDebug() zeroes the core-dump limit.
        _exit(rl.rlim_cur == 0 ? 0 : 1);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}
