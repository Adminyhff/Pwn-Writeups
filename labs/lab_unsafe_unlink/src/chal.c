/* lab_unsafe_unlink —— 自造 unsafe unlink 靶场（amd64 / glibc 2.43）
 *
 * 唯一 bug：
 *   edit(i) 用 read(0, slots[i], sizes[i] + 8) —— 比申请的多写 8 字节，
 *   正好覆盖相邻 chunk 的 size 字段（malloc_usable_size(size) == size，
 *   第 size+1..size+8 字节落在 next chunk 的 size 上）。
 *   del 之后不清 slots[]/sizes[]，于是可以 show/edit 已释放的块（UAF）。
 *
 * 为什么 2.43 上还能 unlink：2.29+ 的 unlink_chunk() 有两组检查
 *     if (chunksize (p) != prev_size (next_chunk (p)))   -> corrupted size vs. prev_size
 *     if (FD->bk != p || BK->fd != p)                    -> corrupted double-linked list
 *   本题把 p->fd / p->bk 写成「指向存放 p 的那个全局槽位」：
 *     FD = &slots[0] - 0x18   BK = &slots[0] - 0x10
 *   →  FD->bk == *(FD + 0x18) == slots[0] == p
 *      BK->fd == *(BK + 0x10) == slots[0] == p
 *   两组检查都通过，unlink 结束后 slots[0] 被写成 FD，得到一个
 *   「指向 .bss 附近」的伪指针 —— 之后 edit(0) 就能改 slots[0] 自己。
 *
 * 预期利用（exp.py）：
 *   16 个 0xf8 块填满 tcache[0x100]   # 否则 free(a) 会进 tcache，不会触发 unlink
 *   add(16)=a, add(17)=b, add(18)=c   # 三个相邻 0x100 chunk
 *   del(16)                            # a 进 unsorted bin
 *   edit(16, FD|BK|...|0x100|0x100)    # a->fd/a->bk 伪造 + b.prev_inuse=0 + b.prev_size=0x100
 *   del(17)                            # 向后合并触发 unlink(a) → slots[0] = FD
 *   edit(16, ...)                      # slots[0] 改成 &handlers
 *   edit(16, p64(win))                 # handlers[0] = win
 *   trigger(0)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXN  64
#define MAXSZ 0x200

static char *slots[MAXN];
static size_t sizes[MAXN];

/* 劫持目标：在 .bss 里，和 slots[] 同一页，便于 unlink 的伪指针落点可控 */
static void (*handlers[8])(const char *) __attribute__((aligned(16)));

static void echo_handler(const char *s) { printf("slot says: %s\n", s); }

static void win(const char *s) {
    (void)s;
    puts("[+] handlers[0] == win, here is your flag:");
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

static void add_slot(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN) { puts("bad index"); return; }
    if (slots[i]) { puts("slot busy"); return; }
    printf("size: ");
    int sz = read_int();
    if (sz < 0x10 || sz > MAXSZ) { puts("bad size"); return; }
    char *p = malloc((size_t)sz);
    if (!p) { puts("oom"); return; }
    printf("data: ");
    if (read(0, p, (size_t)sz) != sz) exit(0);   /* 定长读，EXP 按 size 发字节 */
    slots[i] = p;
    sizes[i] = (size_t)sz;
}

static void edit_slot(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !slots[i]) { puts("no slot"); return; }
    printf("data: ");
    /* ← 全部漏洞：比 sizes[i] 多写 8 字节，覆盖 next chunk 的 size */
    if (read(0, slots[i], sizes[i] + 8) <= 0) exit(0);
    puts("done");
}

static void del_slot(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !slots[i]) { puts("no slot"); return; }
    free(slots[i]);
    /* 不清空 slots[i] / sizes[i] → UAF：可 show / edit 已释放的块 */
    puts("done");
}

static void show_slot(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !slots[i]) { puts("no slot"); return; }
    printf("data: ");
    write(1, slots[i], sizes[i]);
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
    puts("== lab_unsafe_unlink ==");
    for (;;) {
        puts("1. add  2. show  3. edit  4. del  5. trigger  6. exit");
        printf("choice: ");
        switch (read_int()) {
        case 1: add_slot();  break;
        case 2: show_slot(); break;
        case 3: edit_slot(); break;
        case 4: del_slot();  break;
        case 5: trigger();   break;
        case 6: return 0;
        default: puts("??");
        }
    }
}
