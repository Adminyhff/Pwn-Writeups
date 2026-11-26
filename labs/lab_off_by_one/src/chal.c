/* lab_off_by_one —— 自造 off-by-one（1 字节溢出 → chunk overlap）靶场
 * amd64 / glibc 2.43
 *
 * 唯一 bug：
 *   edit(i) 用 read(0, cards[i], sizes[i] + 1) 读 data —— 比申请的多读 1 字节。
 *   malloc_usable_size(请求 size) 恰好等于 size（glibc 允许借用下一块的
 *   prev_size 字段），所以第 size+1 个字节正好落在**相邻 chunk 的 size 最低字节**上。
 *
 * 两步组合（本 lab 的教学重点）：
 *   1) 把相邻 chunk 的 size 0x31 改成 0x61（只改 LSB，prev_inuse 位仍为 1），
 *      这个“变大”的 chunk 之后会被 free 进 tcache[0x60]；
 *   2) 再 malloc(0x58) 取回它时，可写范围覆盖到它后面那个 chunk 的
 *      prev_size / size / tcache_entry.next —— 即 chunk overlap，
 *      接下来就是标准的 safe-linking tcache poisoning。
 *
 * 预期利用（exp.py）：
 *   add(0..3, 0x28)              # 四个 0x30 chunk；chunk3 只是安全边界
 *   edit(0, 'A'*0x28 + '\x61')   # chunk1.size: 0x31 -> 0x61
 *   del(1)                       # tcache[0x60] <- chunk1
 *   del(2)                       # tcache[0x30] <- chunk2
 *   show(2, 8)                   # page = chunk2 >> 12（safe-linking key）
 *   add(4, 0x58, payload)        # 取回 chunk1，覆写 chunk2.size 与 next
 *   add(5, 0x28)                 # 弹出 chunk2，tcache 头变成 &handlers
 *   add(6, 0x28, p64(win))       # malloc 落到 .bss handlers[]
 *   trigger(0)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXN  16
#define MAXSZ 0x100

static char *cards[MAXN];
static size_t sizes[MAXN];

/* 劫持目标：16 字节对齐 —— tcache_get() 的 aligned_OK(e) 会检查；
 * 且 &handlers + 8 必须在映射内，因为 tcache_get() 还会回写 e->key = 0。 */
static void (*handlers[8])(const char *) __attribute__((aligned(16)));

static void echo_handler(const char *s) { printf("card says: %s\n", s); }

static void win(const char *s) {
    (void)s;
    puts("[+] handlers[.] == win, here is your flag:");
    system("cat flag.txt");
}

/* 逐字节读到换行：一次 read 吞掉多行会造成菜单 desync */
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

static void add_card(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN) { puts("bad index"); return; }
    if (cards[i]) { puts("slot busy"); return; }
    printf("size: ");
    int sz = read_int();
    if (sz < 0x10 || sz > MAXSZ) { puts("bad size"); return; }
    char *p = malloc((size_t)sz);
    if (!p) { puts("oom"); return; }
    printf("data: ");
    if (read(0, p, (size_t)sz) != sz) exit(0);   /* 定长读，EXP 按 size 发字节 */
    cards[i] = p;
    sizes[i] = (size_t)sz;
}

static void edit_card(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !cards[i]) { puts("no card"); return; }
    printf("data: ");
    /* ← 全部漏洞：比 sizes[i] 多读 1 字节，正好改写相邻 chunk 的 size LSB */
    if (read(0, cards[i], sizes[i] + 1) <= 0) exit(0);
    puts("done");
}

static void del_card(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !cards[i]) { puts("no card"); return; }
    free(cards[i]);
    /* 不清空 cards[i] / sizes[i] → 可 show 已释放块（泄漏 safe-linking key） */
    puts("done");
}

static void show_card(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !cards[i]) { puts("no card"); return; }
    printf("data: ");
    write(1, cards[i], sizes[i]);
    putchar('\n');
}

static void trigger(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= 8 || !handlers[i]) { puts("no handler"); return; }
    handlers[i]("triggered");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = 0; i < 8; i++) handlers[i] = echo_handler;
    puts("== lab_off_by_one ==");
    for (;;) {
        puts("1. add  2. show  3. edit  4. del  5. trigger  6. exit");
        printf("choice: ");
        switch (read_int()) {
        case 1: add_card();  break;
        case 2: show_card(); break;
        case 3: edit_card(); break;
        case 4: del_card();  break;
        case 5: trigger();   break;
        case 6: return 0;
        default: puts("??");
        }
    }
}
