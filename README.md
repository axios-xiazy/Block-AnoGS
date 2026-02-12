# 🔥 block-anogs.hpp - Anti-Cheat Bypass

---

## 🚀 Quick Start / วิธีใช้ / Cách sử dụng / 快速开始

### English
```cpp
#include "block-anogs.hpp"

__attribute__((constructor)) void init() {
    std::thread(nukeLibrary, "libanogs.so").detach();
}
```

### ไทย
```cpp
#include "block-anogs.hpp"

__attribute__((constructor)) void init() {
    std::thread(nukeLibrary, "libanogs.so").detach();
}
```
เพียงแค่ include header และเรียก `nukeLibrary()` ใน thread แยก พร้อมใส่ชื่อ library ที่ต้องการปิดการทำงาน

### Tiếng Việt
```cpp
#include "block-anogs.hpp"

__attribute__((constructor)) void init() {
    std::thread(nukeLibrary, "libanogs.so").detach();
}
```
Chỉ cần include header và gọi `nukeLibrary()` trong thread riêng, với tên thư viện cần vô hiệu hóa

### 中文
```cpp
#include "block-anogs.hpp"

__attribute__((constructor)) void init() {
    std::thread(nukeLibrary, "libanogs.so").detach();
}
```
只需包含头文件并在独立线程中调用 `nukeLibrary()`，传入要禁用的库名称

---

## 🛡️ How It Works (11 Defense Layers)

### Layer 1: File Permission Lock
- `chmod(path, 0000)` - Removes all permissions
- `utimensat()` - Restores original timestamps to hide traces
- Result: File exists but cannot be opened by anyone

### Layer 2: File Descriptor Exhaustion
- Opens `/dev/null` repeatedly until reaching fd limit
- Leaves only 50 fds available
- Result: Anti-cheat cannot open files for scanning

### Layer 3: Memory Lock
- `mlock()` entire library into RAM
- Prevents swapping to disk
- Result: Cannot dump from swapfile

### Layer 4: ELF Header Destruction
- Overwrites first 64 bytes with zeros
- Inserts fake `\x7fELF` magic
- Result: Dumped file is not recognizable as ELF

### Layer 5: Section Header Removal
- Sets `e_shoff`, `e_shnum`, `e_shstrndx` to 0
- Result: No symbol table, cannot be reverse engineered

### Layer 6: Guard Pages
- `mmap(PROT_NONE)` page right after library
- Result: Any read past library = immediate SIGSEGV crash

### Layer 7: Link Map Hiding
- Unlinks from `dl_iterate_phdr` list
- Result: Hidden from library enumeration APIs

### Layer 8: Anti-Debug
- `PR_SET_DUMPABLE` - Blocks `/proc/[pid]/mem` access
- `ptrace(PTRACE_TRACEME)` - Prevents debugger attachment
- `RLIMIT_CORE` - Disables core dumps
- Result: Cannot attach debugger or dump memory

### Layer 9: Signal Handlers
- Catches SIGTRAP and SIGILL
- Silently skips over them
- Result: Anti-debug traps are neutralized

### Layer 10: Seccomp BPF Sandbox
- Blocks syscalls: `open`, `openat`, `openat2`, `getdents64`
- Blocks: `execve`, `execveat`, `ptrace`
- Blocks: `process_vm_readv/writev`, `memfd_create`
- Result: One-way jail, cannot open files or spawn processes

### Layer 11: Watchdog Thread
- Monitors `/proc/self/maps` every second
- Re-destroys headers if library is detected
- Result: Continuous protection even if restored

---

## 🇹🇭 ไทย - วิธีการทำงาน (11 ชั้นป้องกัน)

### ชั้นที่ 1: ล็อกสิทธิ์ไฟล์
- `chmod(path, 0000)` - ลบสิทธิ์ทั้งหมด
- `utimensat()` - คืนค่า timestamp เดิมเพื่อซ่อนร่องรอย
- ผล: ไฟล์อยู่แต่เปิดไม่ได้

### ชั้นที่ 2: เติม File Descriptor จนเต็ม
- เปิด `/dev/null` ซ้ำๆ จนถึงขีดจำกัด
- เหลือไว้แค่ 50 fds
- ผล: Anti-cheat เปิดไฟล์ตรวจสอบไม่ได้

### ชั้นที่ 3: ล็อกหน่วยความจำ
- `mlock()` ทั้ง library ไว้ใน RAM
- ป้องกันการ swap ออกไป disk
- ผล: ดึงจาก swapfile ไม่ได้

### ชั้นที่ 4: ทำลาย ELF Header
- เขียนทับ 64 ไบต์แรกด้วยศูนย์
- ใส่ magic `\x7fELF` ปลอม
- ผล: ไฟล์ที่ dump ออกมาอ่านไม่รู้เรื่อง

### ชั้นที่ 5: ลบ Section Header
- ตั้งค่า `e_shoff`, `e_shnum`, `e_shstrndx` เป็น 0
- ผล: ไม่มีตารางสัญลักษณ์  reverse ยาก

### ชั้นที่ 6: Guard Pages
- `mmap(PROT_NONE)` หน้าหลัง library
- ผล: อ่านเกิน library มา = crash ทันที

### ชั้นที่ 7: ซ่อนจาก Link Map
- ตัดออกจากลิสต์ `dl_iterate_phdr`
- ผล: ซ่อนจาก API นับ library

### ชั้นที่ 8: ป้องกัน Debug
- `PR_SET_DUMPABLE` - บล็อก `/proc/[pid]/mem`
- `ptrace(PTRACE_TRACEME)` - ป้องกัน debugger attach
- `RLIMIT_CORE` - ปิด core dump
- ผล: attach debugger หรือ dump memory ไม่ได้

### ชั้นที่ 9: จัดการ Signal
- ดัก SIGTRAP และ SIGILL
- ข้ามผ่านเงียบๆ
- ผล: กับดัก anti-debug ใช้ไม่ได้

### ชั้นที่ 10: Seccomp BPF Sandbox
- บล็อก syscalls: `open`, `openat`, `openat2`, `getdents64`
- บล็อก: `execve`, `execveat`, `ptrace`
- บล็อก: `process_vm_readv/writev`, `memfd_create`
- ผล: คุกทางเดียว เปิดไฟล์หรือ spawn process ไม่ได้

### ชั้นที่ 11: Watchdog Thread
- ตรวจ `/proc/self/maps` ทุกวินาที
- ทำลาย headers ซ้ำถ้าพบ library
- ผล: ป้องกันต่อเนื่องแม้ถูก restore

---

## 🇻🇳 Tiếng Việt - Cách hoạt động (11 lớp phòng thủ)

### Lớp 1: Khóa quyền tệp
- `chmod(path, 0000)` - Xóa tất cả quyền
- `utimensat()` - Khôi phục timestamp gốc để che dấu
- Kết quả: Tệp tồn tại nhưng không thể mở

### Lớp 2: Cạn kiệt File Descriptor
- Mở `/dev/null` lặp đi lặp lại đến giới hạn
- Chỉ để lại 50 fds
- Kết quả: Anti-cheat không thể mở tệp để quét

### Lớp 3: Khóa bộ nhớ
- `mlock()` toàn bộ thư viện vào RAM
- Ngăn chuyển sang disk (swap)
- Kết quả: Không thể dump từ swapfile

### Lớp 4: Phá hủy ELF Header
- Ghi đè 64 byte đầu bằng zeros
- Chèn magic `\x7fELF` giả
- Kết quả: Tệp dump không nhận dạng được

### Lớp 5: Xóa Section Header
- Đặt `e_shoff`, `e_shnum`, `e_shstrndx` về 0
- Kết quả: Không có bảng ký hiệu, không reverse được

### Lớp 6: Guard Pages
- `mmap(PROT_NONE)` ngay sau thư viện
- Kết quả: Đọc quá giới hạn = crash ngay

### Lớp 7: Ẩn khỏi Link Map
- Xóa khỏi danh sách `dl_iterate_phdr`
- Kết quả: Ẩn khỏi API liệt kê thư viện

### Lớp 8: Chống Debug
- `PR_SET_DUMPABLE` - Chặn `/proc/[pid]/mem`
- `ptrace(PTRACE_TRACEME)` - Ngăn debugger attach
- `RLIMIT_CORE` - Tắt core dump
- Kết quả: Không attach debugger hoặc dump memory

### Lớp 9: Xử lý Signal
- Bắt SIGTRAP và SIGILL
- Nhảy qua silently
- Kết quả: Bẫy anti-debug bị vô hiệu hóa

### Lớp 10: Seccomp BPF Sandbox
- Chặn syscalls: `open`, `openat`, `openat2`, `getdents64`
- Chặn: `execve`, `execveat`, `ptrace`
- Chặn: `process_vm_readv/writev`, `memfd_create`
- Kết quả: Nhà tù một chiều, không mở tệp hoặc spawn process

### Lớp 11: Watchdog Thread
- Giám sát `/proc/self/maps` mỗi giây
- Phá hủy headers lại nếu phát hiện thư viện
- Kết quả: Bảo vệ liên tục ngay cả khi được restore

---

## 🇨🇳 中文 - 工作原理 (11层防御)

### 第1层：文件权限锁定
- `chmod(path, 0000)` - 移除所有权限
- `utimensat()` - 恢复原始时间戳以隐藏痕迹
- 结果：文件存在但无法打开

### 第2层：文件描述符耗尽
- 重复打开 `/dev/null` 直到达到限制
- 只保留50个fd
- 结果：反作弊无法打开文件进行扫描

### 第3层：内存锁定
- `mlock()` 将整个库锁定到RAM
- 防止交换到磁盘
- 结果：无法从交换文件转储

### 第4层：ELF头部销毁
- 用零覆盖前64字节
- 插入伪造的 `\x7fELF` 魔数
- 结果：转储的文件无法识别为ELF

### 第5层：节头移除
- 将 `e_shoff`、`e_shnum`、`e_shstrndx` 设为0
- 结果：没有符号表，无法逆向工程

### 第6层：保护页
- 在库之后 `mmap(PROT_NONE)` 页面
- 结果：读取超出库范围 = 立即SIGSEGV崩溃

### 第7层：链接映射隐藏
- 从 `dl_iterate_phdr` 列表中取消链接
- 结果：对库枚举API隐藏

### 第8层：反调试
- `PR_SET_DUMPABLE` - 阻止 `/proc/[pid]/mem` 访问
- `ptrace(PTRACE_TRACEME)` - 防止调试器附加
- `RLIMIT_CORE` - 禁用核心转储
- 结果：无法附加调试器或转储内存

### 第9层：信号处理
- 捕获SIGTRAP和SIGILL
- 静默跳过
- 结果：反调试陷阱被中和

### 第10层：Seccomp BPF沙盒
- 阻止系统调用：`open`、`openat`、`openat2`、`getdents64`
- 阻止：`execve`、`execveat`、`ptrace`
- 阻止：`process_vm_readv/writev`、`memfd_create`
- 结果：单向监狱，无法打开文件或生成进程

### 第11层：看门狗线程
- 每秒监控 `/proc/self/maps`
- 如果检测到库则重新销毁头部
- 结果：即使被恢复也能持续保护

---

## ⚠️ Warning / คำเตือน / Cảnh báo / 警告

**English**: This is a ONE-WAY operation. Once `nukeLibrary()` is called, the process cannot open new files, spawn processes, or be debugged. Make sure all initialization is complete before calling.

**ไทย**: นี่เป็นการดำเนินการทางเดียว เมื่อเรียก `nukeLibrary()` แล้ว process จะเปิดไฟล์ใหม่ spawn process หรือถูก debug ไม่ได้ ต้องโหลดทุกอย่างให้เสร็จก่อนเรียก

**Tiếng Việt**: Đây là thao tác MỘT CHIỀU. Sau khi gọi `nukeLibrary()`, process không thể mở tệp mới, spawn process hoặc bị debug. Hãy đảm bảo khởi tạo xong trước khi gọi.

**中文**: 这是单向操作。调用 `nukeLibrary()` 后，进程无法打开新文件、生成进程或被调试。确保在调用前完成所有初始化。

---

## 🎯 Supported Games / เกมที่รองรับ / Game hỗ trợ / 支持的游戏

- Arena of Valor (AOV) / 传说对决 / Liên Quân Mobile / 王者荣耀国际版
- Realm of Valor (ROV)
- Mobile Legends (with caution)
- PUBG Mobile (with additional hiding)

---

<p align="center">
  <b>🔥 Made for Game Modders 🔥</b><br>
  <i>"If they want to scan us, make them unable to scan"</i>
</p>
