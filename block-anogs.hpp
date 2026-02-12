#pragma once

#include <string>
#include <fstream>
#include <thread>
#include <vector>
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

namespace nuke {
    inline volatile sig_atomic_t blocked = 0;
    inline void* lib_base = nullptr;
    inline size_t lib_size = 0;
    inline struct link_map* lm = nullptr;
    inline std::vector<int> dummy_fds;
}

inline std::string getLibraryPath(const std::string& name) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    
    while (std::getline(maps, line)) {
        if (line.find(name) == std::string::npos) continue;
        
        size_t path_start = line.find('/');
        if (path_start == std::string::npos) continue;
        
        size_t path_end = line.find(' ', path_start);
        if (path_end != std::string::npos) {
            return line.substr(path_start, path_end - path_start);
        }
        return line.substr(path_start);
    }
    return "";
}

inline void getLibraryInfo(const std::string& name, void** base, size_t* size) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    *base = nullptr;
    *size = 0;
    
    unsigned long first_start = 0;
    unsigned long last_end = 0;
    bool found = false;
    
    while (std::getline(maps, line)) {
        if (line.find(name) == std::string::npos) continue;
        
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
        *base = reinterpret_cast<void*>(first_start);
        *size = last_end - first_start;
    }
}

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

inline void setupSignalHandlers() {
    struct sigaction sa;
    sa.sa_sigaction = sigTrapHandler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTRAP, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
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

inline void preventPtrace() {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
        _exit(-1);
    }
}

inline int dlPhdrCallback(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    const char* target = static_cast<const char*>(data);
    if (strstr(info->dlpi_name, target)) {
        nuke::lm = reinterpret_cast<struct link_map*>(info->dlpi_addr);
    }
    return 0;
}

inline void hideFromLinkMap(const std::string& name) {
    dl_iterate_phdr(dlPhdrCallback, const_cast<char*>(name.c_str()));
    if (!nuke::lm || !nuke::lm->l_prev) return;
    
    nuke::lm->l_prev->l_next = nuke::lm->l_next;
    if (nuke::lm->l_next) {
        nuke::lm->l_next->l_prev = nuke::lm->l_prev;
    }
}

inline void exhaustFileDescriptors() {
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    
    int dev_null = open("/dev/null", O_RDONLY);
    if (dev_null < 0) return;
    
    while (nuke::dummy_fds.size() < rl.rlim_cur - 50) {
        int fd = dup(dev_null);
        if (fd < 0) break;
        nuke::dummy_fds.push_back(fd);
    }
    close(dev_null);
}

inline void installGuardPages() {
    if (!nuke::lib_base || !nuke::lib_size) return;
    
    unsigned char* end = static_cast<unsigned char*>(nuke::lib_base) + nuke::lib_size;
    end = reinterpret_cast<unsigned char*>((reinterpret_cast<unsigned long>(end) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
    
    mmap(end, PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
}

inline void installSeccompFilter() {
#if defined(__arm__)
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, static_cast<unsigned int>(offsetof(seccomp_data, nr))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_OPENAT, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_OPEN, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_OPENAT2, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_GETDENTS64, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_EXECVE, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_EXECVEAT, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_PTRACE, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_PROCESS_VM_WRITEV, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_PROCESS_VM_READV, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_MEMFD_CREATE, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
#else
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, static_cast<unsigned int>(offsetof(seccomp_data, nr))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_OPENAT, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_OPENAT2, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_GETDENTS64, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_EXECVE, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_EXECVEAT, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_PTRACE, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_PROCESS_VM_WRITEV, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_PROCESS_VM_READV, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, NR_MEMFD_CREATE, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
#endif

    const unsigned short filter_len = sizeof(filter) / sizeof(filter[0]);
    struct sock_fprog prog = { filter_len, filter };
    
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(NR_SECCOMP, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
}

inline void destroyElfHeaders() {
    if (!nuke::lib_base) return;
    
    mprotect(nuke::lib_base, PAGE_SIZE, PROT_READ | PROT_WRITE);
    memset(nuke::lib_base, 0, ELF_HEADER_SIZE);
    
    unsigned char fake_elf[] = {0x7f, 'E', 'L', 'F', 0, 0, 0, 0};
    memcpy(nuke::lib_base, fake_elf, 8);
    
    mprotect(nuke::lib_base, PAGE_SIZE, PROT_READ);
}

inline void hideSectionHeaders() {
    if (!nuke::lib_base) return;
    
    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(nuke::lib_base);
    if (!ehdr->e_shoff) return;
    
    mprotect(nuke::lib_base, PAGE_SIZE, PROT_READ | PROT_WRITE);
    ehdr->e_shoff = 0;
    ehdr->e_shnum = 0;
    ehdr->e_shstrndx = 0;
    mprotect(nuke::lib_base, PAGE_SIZE, PROT_READ);
}

inline void installWatchdog(const std::string& name) {
    std::thread([name]() {
        while (true) {
            sleep(1);
            std::ifstream maps("/proc/self/maps");
            std::string line;
            while (std::getline(maps, line)) {
                if (line.find(name) != std::string::npos && line.find("r-xp") != std::string::npos) {
                    destroyElfHeaders();
                    break;
                }
            }
        }
    }).detach();
}

inline void lockFilePermissions(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return;
    
    struct timespec orig_times[2];
    orig_times[0] = st.st_atim;
    orig_times[1] = st.st_mtim;
    
    chmod(path.c_str(), 0000);
    utimensat(AT_FDCWD, path.c_str(), orig_times, 0);
}

inline void setupAntiDebug() {
    prctl(PR_SET_DUMPABLE, 0);
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
    setrlimit(RLIMIT_NPROC, &rl);
    
    preventPtrace();
    setupSignalHandlers();
}

inline void nukeLibrary(const std::string& name) {
    std::string path;
    do {
        path = getLibraryPath(name);
        if (path.empty()) usleep(1000);
    } while (path.empty());
    
    getLibraryInfo(name, &nuke::lib_base, &nuke::lib_size);
    lockFilePermissions(path);
    
    nuke::blocked = 1;
    
    if (nuke::lib_base && nuke::lib_size) {
        mlock(nuke::lib_base, nuke::lib_size);
    }
    
    destroyElfHeaders();
    hideSectionHeaders();
    setupAntiDebug();
    hideFromLinkMap(name);
    
    exhaustFileDescriptors();
    installGuardPages();
    
    installSeccompFilter();
    
    std::thread([path]() { slowFileRead(path); }).detach();
    installWatchdog(name);
}
