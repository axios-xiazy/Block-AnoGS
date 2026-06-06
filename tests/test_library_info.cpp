#include <gtest/gtest.h>

#include <fstream>
#include <string>

#include "block-anogs.hpp"

namespace {

// Returns the basename of the test executable as recorded in /proc/self/maps.
// The executable is always mapped, so this gives a deterministic target for the
// /proc/self/maps parsing helpers.
std::string SelfExeName() {
    char buf[4096];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len <= 0) return "";
    buf[len] = '\0';
    std::string full(buf);
    size_t slash = full.find_last_of('/');
    return slash == std::string::npos ? full : full.substr(slash + 1);
}

}  // namespace

TEST(ParseProcMaps, FindsPathBaseAndSizeForMappedExecutable) {
    const std::string name = SelfExeName();
    ASSERT_FALSE(name.empty());

    MapsInfo info = parseProcMaps(name);

    ASSERT_FALSE(info.path.empty());
    EXPECT_EQ(info.path.front(), '/');
    EXPECT_NE(info.path.find(name), std::string::npos);
    // The path is a single token: no embedded whitespace.
    EXPECT_EQ(info.path.find(' '), std::string::npos);

    EXPECT_NE(info.base, nullptr);
    EXPECT_GT(info.size, 0u);
}

TEST(ParseProcMaps, SpansAllMappingsOfTheModule) {
    const std::string name = SelfExeName();
    MapsInfo info = parseProcMaps(name);
    ASSERT_NE(info.base, nullptr);

    // Independently compute the first start and last end for the module and
    // confirm parseProcMaps reports the full span between them.
    std::ifstream maps("/proc/self/maps");
    std::string line;
    unsigned long first_start = 0, last_end = 0;
    bool found = false;
    while (std::getline(maps, line)) {
        if (line.find(name) == std::string::npos) continue;
        unsigned long start = strtoul(line.c_str(), nullptr, 16);
        size_t dash = line.find('-');
        unsigned long end = strtoul(line.substr(dash + 1).c_str(), nullptr, 16);
        if (!found) { first_start = start; found = true; }
        last_end = end;
    }
    ASSERT_TRUE(found);
    EXPECT_EQ(reinterpret_cast<unsigned long>(info.base), first_start);
    EXPECT_EQ(info.size, last_end - first_start);
}

TEST(ParseProcMaps, ReturnsEmptyInfoForUnknownLibrary) {
    MapsInfo info = parseProcMaps("definitely_not_a_real_library_xyz123.so");

    EXPECT_TRUE(info.path.empty());
    EXPECT_EQ(info.base, nullptr);
    EXPECT_EQ(info.size, 0u);
}

TEST(ParseProcMaps, HandlesEmptyNameWithoutThrowing) {
    // An empty needle matches every line, including anonymous/special mappings
    // such as "[heap]" that contain no '/', so parsing must not crash.
    EXPECT_NO_THROW({ MapsInfo info = parseProcMaps(""); (void)info; });
}

TEST(HasExecutableMapping, TrueForMappedExecutable) {
    const std::string name = SelfExeName();
    ASSERT_FALSE(name.empty());
    // The test binary always has an r-xp (executable) mapping of itself.
    EXPECT_TRUE(hasExecutableMapping(name));
}

TEST(HasExecutableMapping, FalseForUnknownLibrary) {
    EXPECT_FALSE(hasExecutableMapping("definitely_not_a_real_library_xyz123.so"));
}
