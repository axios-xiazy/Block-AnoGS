#include <gtest/gtest.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "block-anogs.hpp"

namespace {

std::string MakeTempFile(const char* contents) {
    char tmpl[] = "/tmp/block_anogs_testXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return "";
    if (contents && *contents) {
        ssize_t n = write(fd, contents, strlen(contents));
        (void)n;
    }
    close(fd);
    return std::string(tmpl);
}

}  // namespace

TEST(LockFilePermissions, RemovesAllPermissions) {
    std::string path = MakeTempFile("payload");
    ASSERT_FALSE(path.empty());

    lockFilePermissions(path);

    struct stat st;
    ASSERT_EQ(stat(path.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0u);

    // Restore so we can clean up reliably.
    chmod(path.c_str(), 0600);
    unlink(path.c_str());
}

TEST(LockFilePermissions, PreservesTimestamps) {
    std::string path = MakeTempFile("payload");
    ASSERT_FALSE(path.empty());

    struct stat before;
    ASSERT_EQ(stat(path.c_str(), &before), 0);

    // Make sure some wall-clock time would pass so a naive implementation that
    // doesn't restore timestamps would visibly bump mtime.
    sleep(1);
    lockFilePermissions(path);

    struct stat after;
    ASSERT_EQ(stat(path.c_str(), &after), 0);
    EXPECT_EQ(before.st_mtim.tv_sec, after.st_mtim.tv_sec);
    EXPECT_EQ(before.st_atim.tv_sec, after.st_atim.tv_sec);

    chmod(path.c_str(), 0600);
    unlink(path.c_str());
}

TEST(LockFilePermissions, NoOpForMissingFile) {
    EXPECT_NO_THROW(lockFilePermissions("/tmp/block_anogs_does_not_exist_xyz"));
}

TEST(SlowFileRead, ReadsExistingFileWithoutError) {
    // Keep the file tiny: slowFileRead sleeps 100ms per 4096-byte chunk.
    std::string path = MakeTempFile("hello");
    ASSERT_FALSE(path.empty());

    EXPECT_NO_THROW(slowFileRead(path));

    unlink(path.c_str());
}

TEST(SlowFileRead, ReturnsImmediatelyForMissingFile) {
    EXPECT_NO_THROW(slowFileRead("/tmp/block_anogs_does_not_exist_xyz"));
}

// exhaustFileDescriptors() consumes available fds but deliberately leaves a
// 50-fd headroom. Run it in a child with a small RLIMIT_NOFILE so the test
// process is unaffected, and verify both the count and the preserved headroom.
TEST(ExhaustFileDescriptors, FillsFdTableButLeavesReservedHeadroom) {
    pid_t pid = fork();
    ASSERT_GE(pid, 0);

    if (pid == 0) {
        const rlim_t limit = 96;
        struct rlimit rl;
        rl.rlim_cur = limit;
        rl.rlim_max = limit;
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) _exit(2);

        nuke::dummy_fds.clear();
        exhaustFileDescriptors();

        // It stops once it has opened (limit - 50) dummy fds.
        if (nuke::dummy_fds.size() != static_cast<size_t>(limit - 50)) _exit(3);

        // The reserved headroom means a fresh open() must still succeed.
        int extra = open("/dev/null", O_RDONLY);
        if (extra < 0) _exit(4);
        close(extra);

        _exit(0);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}
