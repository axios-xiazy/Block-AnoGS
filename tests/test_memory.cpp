#include <gtest/gtest.h>

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>

#include "block-anogs.hpp"

namespace {

// Restores the global nuke state between tests so cases stay independent.
class MemoryFixture : public ::testing::Test {
protected:
    void SetUp() override {
        nuke::lib_base = nullptr;
        nuke::lib_size = 0;
    }
    void TearDown() override {
        nuke::lib_base = nullptr;
        nuke::lib_size = 0;
    }
};

}  // namespace

TEST_F(MemoryFixture, DestroyElfHeadersWritesFakeMagicAndZeroesRest) {
    void* page = mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(page, MAP_FAILED);
    memset(page, 0xAB, PAGE_SIZE);

    nuke::lib_base = page;
    nuke::lib_size = PAGE_SIZE;

    destroyElfHeaders();

    const unsigned char* bytes = static_cast<const unsigned char*>(page);
    const unsigned char expected_magic[] = {0x7f, 'E', 'L', 'F'};
    EXPECT_EQ(memcmp(bytes, expected_magic, 4), 0);
    for (size_t i = 8; i < ELF_HEADER_SIZE; ++i) {
        EXPECT_EQ(bytes[i], 0u) << "byte " << i << " was not zeroed";
    }
    // Memory past the destroyed header is untouched.
    EXPECT_EQ(bytes[ELF_HEADER_SIZE], 0xABu);

    munmap(page, PAGE_SIZE);
}

TEST_F(MemoryFixture, DestroyElfHeadersNoOpWhenBaseNull) {
    EXPECT_NO_THROW(destroyElfHeaders());
}

TEST_F(MemoryFixture, HideSectionHeadersZeroesSectionFields) {
    void* page = mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(page, MAP_FAILED);
    memset(page, 0, PAGE_SIZE);

    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(page);
    ehdr->e_shoff = 0x1000;
    ehdr->e_shnum = 42;
    ehdr->e_shstrndx = 7;

    nuke::lib_base = page;
    nuke::lib_size = PAGE_SIZE;

    hideSectionHeaders();

    EXPECT_EQ(ehdr->e_shoff, 0u);
    EXPECT_EQ(ehdr->e_shnum, 0u);
    EXPECT_EQ(ehdr->e_shstrndx, 0u);

    munmap(page, PAGE_SIZE);
}

TEST_F(MemoryFixture, HideSectionHeadersNoOpWhenSectionOffsetAlreadyZero) {
    void* page = mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(page, MAP_FAILED);
    memset(page, 0, PAGE_SIZE);

    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(page);
    ehdr->e_shoff = 0;
    ehdr->e_shnum = 5;  // Should remain untouched because of the early return.

    nuke::lib_base = page;
    nuke::lib_size = PAGE_SIZE;

    hideSectionHeaders();

    EXPECT_EQ(ehdr->e_shnum, 5u);

    munmap(page, PAGE_SIZE);
}

TEST_F(MemoryFixture, HideSectionHeadersNoOpWhenBaseNull) {
    EXPECT_NO_THROW(hideSectionHeaders());
}

TEST_F(MemoryFixture, InstallGuardPagesNoOpWhenBaseNull) {
    EXPECT_NO_THROW(installGuardPages());
}

// The guard page must be unreadable: touching it should raise SIGSEGV. Verify
// in a child process so the fault doesn't take down the test runner.
TEST_F(MemoryFixture, InstallGuardPagesMakesTrailingPageInaccessible) {
    // Reserve two contiguous pages; treat the first as the "library".
    void* region = mmap(nullptr, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(region, MAP_FAILED);

    nuke::lib_base = region;
    nuke::lib_size = PAGE_SIZE;  // guard page lands on the second page

    installGuardPages();

    unsigned char* guard = static_cast<unsigned char*>(region) + PAGE_SIZE;

    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        volatile unsigned char sink = *guard;  // expected to SIGSEGV
        (void)sink;
        _exit(0);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    EXPECT_TRUE(WIFSIGNALED(status));
    EXPECT_EQ(WTERMSIG(status), SIGSEGV);

    munmap(region, PAGE_SIZE * 2);
}
