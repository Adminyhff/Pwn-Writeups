/* lab_tcache_poisoning —— 自造 tcache poisoning 靶场（amd64, glibc 2.3x）
 *
 * 教学点（与真实赛题一致的最小集合）：
 *   1) free() 之后不清空 notes[] → UAF：已释放的 chunk 仍可 show / edit；
 *   2) glibc >= 2.32 的 tcache 使用 safe-linking：
 *        e->next = next ^ (e >> 12)
 *      只要把 tcache 队尾 chunk 的 next 改掉，就能让 malloc 返回任意地址；
 *   3) 自 glibc 2.34 起 __free_hook / __malloc_hook 已被移除，
 *      所以这里用 .bss 里的函数指针 fh.fn 顶替 hook 的角色（真实题目里
 *      常见替代目标是 exit_funcs / _IO_list_all / 程序自己的函数指针表）。
 *
 * 预期利用：free(0) → show(0) 泄漏 (a >> 12) → free(1) → edit(0) 改写 next
 *           → 连续 3 次 add，第 3 次 malloc 落到 &fh → 写入 backdoor → trigger。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXN   16
#define MAXSZ  0x100

static char *notes[MAXN];
static size_t sizes[MAXN];

/* 16 字节对齐：tcache_get() 会检查 aligned_OK(e)。
 * 写满 0x40 字节的 payload 正好覆盖本结构，不会踩到后面的 .bss 变量。 */
struct fake_hook {
    void (*fn)(void);
    char pad[0x38];
};
struct fake_hook fh __attribute__((aligned(16)));

static void backdoor(void) {
    puts("[+] hook hijacked, here is your flag:");
    system("cat flag.txt");
}

/* 逐字节读到换行：read(0,b,15) 在一次 read 里会把后续已到达的字节一起吞掉，
 * 造成菜单 desync（表现为莫名 "bad size" / "??"），这里必须按字节消费。 */
static int read_int(void) {
    char b[16];
    int n = 0;
    char c;
    while (n < (int)sizeof(b) - 1) {
        if (read(0, &c, 1) <= 0) exit(0);
        if (c == '\n') break;
        b[n++] = c;
    }
    b[n] = '\0';
    return atoi(b);
}

static void add_note(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN) { puts("bad index"); return; }
    if (notes[i]) { puts("slot busy"); return; }
    printf("size: ");
    int sz = read_int();
    if (sz <= 0 || sz > MAXSZ) { puts("bad size"); return; }
    char *p = malloc(sz);
    if (!p) { puts("oom"); return; }
    notes[i] = p;
    sizes[i] = (size_t)sz;
    printf("data: ");
    read(0, p, (size_t)sz);
}

static void edit_note(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !notes[i]) { puts("no note"); return; }
    printf("data: ");
    /* UAF 写：已经 free 的 chunk 照样能改，tcache 的 next 就在开头 8 字节 */
    read(0, notes[i], sizes[i]);
}

static void del_note(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !notes[i]) { puts("no note"); return; }
    free(notes[i]);
    /* 故意不清空 notes[i] / sizes[i]：这就是漏洞 */
    puts("done");
}

static void show_note(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !notes[i]) { puts("no note"); return; }
    /* 定长 write：能读到含 \x00 的 safe-linking 密文 */
    write(1, notes[i], sizes[i]);
    write(1, "\n", 1);
}

static void trigger(void) {
    if (fh.fn) fh.fn();
    else puts("hook is null");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== lab_tcache_poisoning ==");
    puts("note: __free_hook is gone since glibc 2.34, fh.fn plays that role");
    for (;;) {
        puts("1. add  2. edit  3. free  4. show  5. trigger  6. exit");
        printf("choice: ");
        switch (read_int()) {
        case 1: add_note();   break;
        case 2: edit_note();  break;
        case 3: del_note();   break;
        case 4: show_note();  break;
        case 5: trigger();    break;
        case 6: return 0;
        default: puts("??");
        }
    }
}
