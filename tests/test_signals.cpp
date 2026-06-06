#include <gtest/gtest.h>

#include <signal.h>
#include <link.h>

#include <cstring>

#include "block-anogs.hpp"

TEST(SignalHandlers, InstallsSigInfoHandlerForTrapAndIll) {
    setupSignalHandlers();

    struct sigaction current;
    memset(&current, 0, sizeof(current));

    ASSERT_EQ(sigaction(SIGTRAP, nullptr, &current), 0);
    EXPECT_TRUE(current.sa_flags & SA_SIGINFO);
    EXPECT_EQ(current.sa_sigaction, &sigTrapHandler);

    memset(&current, 0, sizeof(current));
    ASSERT_EQ(sigaction(SIGILL, nullptr, &current), 0);
    EXPECT_TRUE(current.sa_flags & SA_SIGINFO);
    EXPECT_EQ(current.sa_sigaction, &sigTrapHandler);
}

TEST(SigTrapHandler, ReturnsEarlyWhenNotBlocked) {
    nuke::blocked = 0;
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    EXPECT_NO_THROW(sigTrapHandler(SIGTRAP, &info, nullptr));
}

TEST(SigTrapHandler, HandlesBlockedStateWithoutCrashing) {
    nuke::blocked = 1;
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    EXPECT_NO_THROW(sigTrapHandler(SIGTRAP, &info, nullptr));
    nuke::blocked = 0;
}

TEST(SetupSignalHandlers, DeliveredTrapIsHandledNotFatal) {
    setupSignalHandlers();
    nuke::blocked = 0;  // handler returns immediately; raise() completes cleanly
    EXPECT_EQ(raise(SIGTRAP), 0);
}

TEST(DlPhdrCallback, RecordsLinkMapWhenNameMatches) {
    nuke::lm = nullptr;

    struct dl_phdr_info info;
    memset(&info, 0, sizeof(info));
    info.dlpi_name = "/usr/lib/libtarget.so.1";
    info.dlpi_addr = static_cast<ElfW(Addr)>(0x4000);

    char target[] = "libtarget";
    int rc = dlPhdrCallback(&info, sizeof(info), target);

    EXPECT_EQ(rc, 0);
    EXPECT_EQ(nuke::lm, reinterpret_cast<struct link_map*>(0x4000));

    nuke::lm = nullptr;
}

TEST(DlPhdrCallback, IgnoresNonMatchingName) {
    nuke::lm = nullptr;

    struct dl_phdr_info info;
    memset(&info, 0, sizeof(info));
    info.dlpi_name = "/usr/lib/libsomethingelse.so";
    info.dlpi_addr = static_cast<ElfW(Addr)>(0x4000);

    char target[] = "libtarget";
    int rc = dlPhdrCallback(&info, sizeof(info), target);

    EXPECT_EQ(rc, 0);
    EXPECT_EQ(nuke::lm, nullptr);
}

TEST(HideFromLinkMap, NoOpForUnknownLibrary) {
    nuke::lm = nullptr;
    // No loaded module matches, so the callback leaves nuke::lm null and the
    // function must hit the early-return guard without touching any list.
    EXPECT_NO_THROW(hideFromLinkMap("definitely_not_a_real_library_xyz123.so"));
    EXPECT_EQ(nuke::lm, nullptr);
}
