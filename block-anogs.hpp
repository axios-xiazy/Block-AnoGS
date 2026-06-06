#pragma once

#include <string>
#include <fstream>
#include <thread>
#include <vector>
#include <atomic>
#include <functional>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/ucontext.h>
#include <signal.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/time.h>

#if defined(__aarch64__)
    constexpr int NR_OPENAT = 56;
    constexpr int NR_OPENAT2 = 437;
    constexpr int NR_EXECVE = 221;
    constexpr int NR_EXECVEAT = 281;
    constexpr int NR_PTRACE = 117;
    constexpr int NR_PROCESS_VM_WRITEV = 271;
    constexpr int NR_PROCESS_VM_READV = 270;
    constexpr int NR_MEMFD_CREATE = 279;
    constexpr int NR_SECCOMP = 277;
    constexpr int NR_GETDENTS64 = 61;
#elif defined(__arm__)
    constexpr int NR_OPENAT = 322;
    constexpr int NR_OPEN = 5;
    constexpr int NR_OPENAT2 = 437;
    constexpr int NR_EXECVE = 11;
    constexpr int NR_EXECVEAT = 387;
    constexpr int NR_PTRACE = 26;
    constexpr int NR_PROCESS_VM_WRITEV = 377;
    constexpr int NR_PROCESS_VM_READV = 376;
    constexpr int NR_MEMFD_CREATE = 385;
    constexpr int NR_SECCOMP = 383;
    constexpr int NR_GETDENTS64 = 141;
#else
    #error "Unsupported architecture"
#endif

#ifndef RLIMIT_NPROC
    #define RLIMIT_NPROC 6
#endif

constexpr size_t ELF_HEADER_SIZE = 64;
constexpr size_t PAGE_SIZE = 4096;
constexpr int MAX_DISCOVERY_RETRIES = 30000;

struct NukeStatus {
    std::atomic<bool> completed{false};
    std::atomic<bool> library_found{false};
    std::atomic<bool> permissions_locked{false};
    std::atomic<bool> memory_locked{false};
    std::atomic<bool> elf_headers_destroyed{false};
    std::atomic<bool> section_headers_hidden{false};
    std::atomic<bool> anti_debug_set{false};
    std::atomic<bool> link_map_hidden{false};
    std::atomic<bool> fd_exhausted{false};
    std::atomic<bool> guard_pages_installed{false};
    std::atomic<bool> seccomp_installed{false};
    std::atomic<bool> watchdog_started{false};
};

namespace nuke {
    inline volatile sig_atomic_t blocked = 0;
    inline void* lib_base = nullptr;
    inline size_t lib_size = 0;
    inline struct link_map* lm = nullptr;
    inline std::vector<int> dummy_fds;
    inline NukeStatus status;
}

// ============================================================
// Shared Utility: /proc/self/maps parser
// ============================================================

struct MapsInfo {
    std::string path;
    void* base;
    size_t size;
};

inline MapsInfo parseProcMaps(const std::string& name) {
    MapsInfo info{"", nullptr, 0};
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return info;
    std::string line;

    unsigned long first_start = 0;
    unsigned long last_end = 0;
    bool found = false;

    while (std::getline(maps, line)) {
        if (line.find(name) == std::string::npos) continue;

        if (info.path.empty()) {
            size_t path_start = line.find('/');
            if (path_start != std::string::npos) {
                size_t path_end = line.find(' ', path_start);
                info.path = (path_end != std::string::npos)
                    ? line.substr(path_start, path_end - path_start)
                    : line.substr(path_start);
            }
        }

        unsigned long start = strtoul(line.c_str(), nullptr, 16);
        size_t dash = line.find('-');
        if (dash == std::string::npos) continue;

        unsigned long end = strtoul(line.substr(dash + 1).c_str(), nullptr, 16);

        if (!found) {
            first_start = start;
            found = true;
        }
        last_end = end;
    }

    if (found) {
        info.base = reinterpret_cast<void*>(first_start);
        info.size = last_end - first_start;
    }
    return info;
}

// ============================================================
// Shared Utility: writable memory guard (mprotect sandwich)
// ============================================================

inline bool withWritableMemory(void* addr, size_t len, const std::function<void()>& fn) {
    if (mprotect(addr, len, PROT_READ | PROT_WRITE) != 0) return false;
    fn();
    mprotect(addr, len, PROT_READ);
    return true;
}

// ============================================================
// Shared Utility: data-driven seccomp BPF filter builder
// ============================================================

inline bool installSeccompFilter() {
    const int blocked_syscalls[] = {
        NR_OPENAT,
#if defined(__arm__)
        NR_OPEN,
#endif
        NR_OPENAT2,
        NR_GETDENTS64,
        NR_EXECVE,
        NR_EXECVEAT,
        NR_PTRACE,
        NR_PROCESS_VM_WRITEV,
        NR_PROCESS_VM_READV,
        NR_MEMFD_CREATE,
    };
    constexpr size_t max_rules = 11;
    // Each blocked syscall = 2 instructions (jump + ret), plus 1 load + 1 allow
    struct sock_filter filter[2 + max_rules * 2];
    unsigned short idx = 0;

    // Load syscall number
    filter[idx++] = BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                             static_cast<unsigned int>(offsetof(seccomp_data, nr)));

    // Generate deny rule for each blocked syscall
    const size_t count = sizeof(blocked_syscalls) / sizeof(blocked_syscalls[0]);
    for (size_t i = 0; i < count; ++i) {
        filter[idx++] = BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                                 static_cast<unsigned int>(blocked_syscalls[i]), 0, 1);
        filter[idx++] = BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM);
    }

    // Default: allow
    filter[idx++] = BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = { idx, filter };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return false;
    return syscall(NR_SECCOMP, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog) == 0;
}

// ============================================================
// Core functions (using shared utilities above)
// ============================================================

inline void sigTrapHandler(int sig, siginfo_t* info, void* context) {
    (void)sig;
    (void)info;

    if (!nuke::blocked) return;

    ucontext_t* uc = static_cast<ucontext_t*>(context);
#if defined(__arm__)
    uc->uc_mcontext.arm_pc += 4;
#elif defined(__aarch64__)
    uc->uc_mcontext.pc += 4;
#endif
}

inline bool setupSignalHandlers() {
    struct sigaction sa;
    sa.sa_sigaction = sigTrapHandler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    bool ok = true;
    if (sigaction(SIGTRAP, &sa, nullptr) != 0) ok = false;
    if (sigaction(SIGILL, &sa, nullptr) != 0) ok = false;
    return ok;
}

inline void slowFileRead(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return;

    char buffer[4096];
    while (read(fd, buffer, sizeof(buffer)) > 0) {
        usleep(100000);
    }
    close(fd);
}

inline bool preventPtrace() {
    return ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) >= 0;
}

inline int dlPhdrCallback(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    const char* target = static_cast<const char*>(data);
    if (strstr(info->dlpi_name, target)) {
        nuke::lm = reinterpret_cast<struct link_map*>(info->dlpi_addr);
    }
    return 0;
}

inline bool hideFromLinkMap(const std::string& name) {
    dl_iterate_phdr(dlPhdrCallback, const_cast<char*>(name.c_str()));
    if (!nuke::lm || !nuke::lm->l_prev) return false;

    nuke::lm->l_prev->l_next = nuke::lm->l_next;
    if (nuke::lm->l_next) {
        nuke::lm->l_next->l_prev = nuke::lm->l_prev;
    }
    return true;
}

inline bool exhaustFileDescriptors() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return false;

    int dev_null = open("/dev/null", O_RDONLY);
    if (dev_null < 0) return false;

    while (nuke::dummy_fds.size() < rl.rlim_cur - 50) {
        int fd = dup(dev_null);
        if (fd < 0) break;
        nuke::dummy_fds.push_back(fd);
    }
    close(dev_null);
    return !nuke::dummy_fds.empty();
}

inline bool installGuardPages() {
    if (!nuke::lib_base || !nuke::lib_size) return false;

    unsigned char* end = static_cast<unsigned char*>(nuke::lib_base) + nuke::lib_size;
    end = reinterpret_cast<unsigned char*>(
        (reinterpret_cast<unsigned long>(end) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));

    void* result = mmap(end, PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    return result != MAP_FAILED;
}

inline bool destroyElfHeaders() {
    if (!nuke::lib_base) return false;

    return withWritableMemory(nuke::lib_base, PAGE_SIZE, []() {
        memset(nuke::lib_base, 0, ELF_HEADER_SIZE);
        unsigned char fake_elf[] = {0x7f, 'E', 'L', 'F', 0, 0, 0, 0};
        memcpy(nuke::lib_base, fake_elf, 8);
    });
}

inline bool hideSectionHeaders() {
    if (!nuke::lib_base) return false;

    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(nuke::lib_base);
    if (!ehdr->e_shoff) return false;

    return withWritableMemory(nuke::lib_base, PAGE_SIZE, [ehdr]() {
        ehdr->e_shoff = 0;
        ehdr->e_shnum = 0;
        ehdr->e_shstrndx = 0;
    });
}

inline bool hasExecutableMapping(const std::string& name) {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(name) != std::string::npos &&
            line.find("r-xp") != std::string::npos) {
            return true;
        }
    }
    return false;
}

inline bool installWatchdog(const std::string& name) {
    std::thread([name]() {
        while (true) {
            sleep(1);
            if (hasExecutableMapping(name)) {
                destroyElfHeaders();
            }
        }
    }).detach();
    return true;
}

inline bool lockFilePermissions(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;

    struct timespec orig_times[2];
    orig_times[0] = st.st_atim;
    orig_times[1] = st.st_mtim;

    if (chmod(path.c_str(), 0000) != 0) return false;
    utimensat(AT_FDCWD, path.c_str(), orig_times, 0);
    return true;
}

inline bool setupAntiDebug() {
    bool ok = true;

    if (prctl(PR_SET_DUMPABLE, 0) != 0) ok = false;
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    struct rlimit rl = {0, 0};
    if (setrlimit(RLIMIT_CORE, &rl) != 0) ok = false;
    setrlimit(RLIMIT_NPROC, &rl);

    if (!preventPtrace()) ok = false;
    if (!setupSignalHandlers()) ok = false;
    return ok;
}

inline bool nukeLibrary(const std::string& name) {
    MapsInfo info;
    int retries = 0;
    do {
        info = parseProcMaps(name);
        if (info.path.empty()) {
            if (++retries > MAX_DISCOVERY_RETRIES) {
                nuke::status.completed.store(true);
                return false;
            }
            usleep(1000);
        }
    } while (info.path.empty());

    nuke::status.library_found.store(true);

    nuke::lib_base = info.base;
    nuke::lib_size = info.size;
    nuke::status.permissions_locked.store(lockFilePermissions(info.path));

    nuke::blocked = 1;

    if (nuke::lib_base && nuke::lib_size) {
        nuke::status.memory_locked.store(mlock(nuke::lib_base, nuke::lib_size) == 0);
    }

    nuke::status.elf_headers_destroyed.store(destroyElfHeaders());
    nuke::status.section_headers_hidden.store(hideSectionHeaders());
    nuke::status.anti_debug_set.store(setupAntiDebug());
    nuke::status.link_map_hidden.store(hideFromLinkMap(name));

    nuke::status.fd_exhausted.store(exhaustFileDescriptors());
    nuke::status.guard_pages_installed.store(installGuardPages());

    nuke::status.seccomp_installed.store(installSeccompFilter());

    std::thread([info]() { slowFileRead(info.path); }).detach();
    nuke::status.watchdog_started.store(installWatchdog(name));

    nuke::status.completed.store(true);
    return nuke::lib_base != nullptr;
}
