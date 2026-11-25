/* lab_fmtstr_read —— 自造格式化字符串“读”靶场（amd64 / glibc 2.43）
 *
 * 只有一个漏洞：printf(buf) 把用户输入当格式串 —— 但**没有任何写原语**，
 * 目标是把 flag 从内存里“读”出来，专门练三件事：
 *   1. %p 扫描栈：认出 canary（0x........00）与 __libc_start_main 返回地址（0x7f..）；
 *   2. 定位自己的输入缓冲区在参数表里的位置（%<k>$...）；
 *   3. %s 任意读：把目标地址放在缓冲区开头，用 %<k>$s 当成指针解引用。
 *
 * 协议（二进制安全，避免地址里的 0x0a 被行读截断）：
 *   先发 4 字节小端长度 len，再发 len 字节内容；程序 printf 出去后回 "\n---\n"。
 *
 * flag 在启动时读进 secret[]（.bss），程序从不打印它 —— 只能靠 %s 读。
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char secret[0x80];            /* .bss：flag 落在这里，不打印 */

static void load_secret(void) {
    FILE *fp = fopen("flag.txt", "r");
    if (!fp) { strcpy(secret, "__PWNED__{no_flag_file}"); return; }
    fread(secret, 1, sizeof(secret) - 1, fp);
    fclose(fp);
}

static int read_n(void *dst, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(0, (char *)dst + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    load_secret();
    puts("== lab_fmtstr_read ==");
    puts("proto: <u32 len><payload>  (echo back through printf(payload))");

    /* 16 字节对齐的**栈**缓冲区：EXP 把 8 字节目标地址放在 buf[0x10]，
     * 这样 %<k+2>$s 才能直接把它当指针用（k = buf 在参数表里的索引）。
     * 注意不能写成 static —— 那样 buffer 会跑到 .bss，%p 扫栈就找不到它了。 */
    char buf[0x100] __attribute__((aligned(16)));

    for (;;) {
        uint32_t len;
        if (read_n(&len, 4) < 0) break;
        if (len == 0 || len >= sizeof(buf)) continue;
        if (read_n(buf, len) < 0) break;
        buf[len] = '\0';
        printf("echo: ");
        printf(buf);                 /* ← 唯一的漏洞 */
        printf("\n---\n");
    }
    return 0;
}
