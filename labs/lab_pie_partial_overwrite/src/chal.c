/* lab_pie_partial_overwrite —— 自造「PIE + 1 字节溢出 → 局部覆盖返回地址」靶场
 * amd64 / PIE / NX / 无 canary / Partial RELRO（glibc 版本无关）
 *
 * 唯一 bug：
 *   vuln() 里 read(0, buf, 0x40 + 8 + 1) —— 缓冲区 0x40，多读 9 字节：
 *   8 字节吃掉 saved rbp，第 9 字节正好落在 **saved rip 的最低字节**上。
 *
 * 为什么这已经够用（本 lab 的教学重点）：
 *   PIE 下地址高字节随机，但 **页内偏移是固定的**（镜像内部布局不随机）。
 *   只要覆盖后的目标与 `vuln` 的返回地址落在同一个 **256 字节块**
 *   （即高位 7 字节相同），1 字节覆盖就能 100% 命中，不需要任何泄漏、
 *   也不需要 1/16 的 nibble 爆破。
 *
 * 预期利用（exp.py）：
 *   发 'A'*0x48 + p8(目标低字节)  → 从 "puts nope" 直接跳进 win 分支读 flag
 *
 * 关键布局约束（改代码后必须重新核对，exp.py 里带断言）：
 *   RET_ADDR = vuln 返回后 main 里的下一条指令
 *   TARGET   = `if (never)` 分支体的入口
 *   (RET_ADDR & ~0xff) == (TARGET & ~0xff)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

/* 恒为 0，但 -O0 不会把它优化成常量 → win 分支的代码一定被保留下来 */
static volatile int never;

__attribute__((noinline)) static void win_path(void) {
    char flag[0x80];
    int fd = open("flag.txt", O_RDONLY);
    if (fd < 0) {
        puts("[!] no flag.txt in cwd");
        _exit(1);
    }
    ssize_t r = read(fd, flag, sizeof(flag) - 1);
    if (r < 0) r = 0;
    close(fd);
    write(1, flag, (size_t)r);
    _exit(0);
}

__attribute__((noinline)) static void vuln(void) {
    char buf[0x40];
    puts("one byte, please:");
    /* ← 全部漏洞：0x40 + 8(rbp) + 1(rip LSB) */
    if (read(0, buf, 0x40 + 8 + 1) <= 0) _exit(1);
}

int main(void) __attribute__((aligned(256)));

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== lab_pie_partial_overwrite ==");
    vuln();
    puts("nope");                 /* 正常路径：打印 nope 后退出 */
    if (never) win_path();        /* 只在 LSB 覆盖到这里时才可达 */
    return 0;
}
