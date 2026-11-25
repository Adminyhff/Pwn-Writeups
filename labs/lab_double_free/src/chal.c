/* lab_double_free —— 自造 double free 靶场（amd64 / glibc 2.43）
 *
 * 两个 bug 组合（现实里都很常见）：
 *   1. secure_free()：free 之前先 memset(ptr, 0, size)。这个“安全清零”动作会
 *      把 tcache_entry.key 一并抹掉，于是 glibc 2.29+ 的
 *        if (e->key == tcache) -> 遍历 bin 找 e -> "double free detected in tcache 2"
 *      检测被绕过（本 lab 的核心）；
 *   2. del 之后不清空 slots[]/sizes[]：既能对同一 index 再次 del，
 *      也能用 show 读已释放 chunk（本 lab 只用它来泄漏 safe-linking 页号）。
 *
 * 预期利用（详见 exp.py / README.md）：
 *   add(0) add(1) -> del(0) -> show(0) 泄漏 safe-linking 页号 page = c0 >> 12
 *   del(1) -> del(0)              # 第三次 free 通过（key 被 memset 清掉）
 *                                 # tcache[0x50] = c0 -> c1 -> c0（环）
 *   add(2, p64(handlers ^ page))  # 取 c0，顺手把它（环里还会再出现）的 next 改成 handlers
 *   add(3)                        # 取 c1
 *   add(4)                        # 再取 c0，此时 tcache 头被读成 handlers
 *   add(5, p64(win))              # malloc 落到 .bss 的 handlers[]，写 win
 *   trigger(0)                    # handlers[0]("triggered") == win -> cat flag.txt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXSLOT 16
#define MAXSZ   0x100

static char *slots[MAXSLOT];
static size_t sizes[MAXSLOT];

/* 触发用的全局函数指针表：16 字节对齐 —— tcache_get() 的 aligned_OK(e) 会检查这一点；
 * handlers[1] 必须在映射内，因为 tcache_get() 还会回写 e->key = 0（即 &handlers + 8）。 */
static void (*handlers[8])(const char *) __attribute__((aligned(16)));

static void echo_handler(const char *s) { printf("slot says: %s\n", s); }

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

/* bug 1：free 前先清零。tcache_put() 依赖 e->key 判断“这块是否已在 bin 里”，
 * 先 memset 等于把这个检测依据擦掉 → 同一块可以连着 free 两次。 */
static void secure_free(void *p, size_t n) {
    if (!p) return;
    memset(p, 0, n);          /* ← 关键：把 tcache_entry 的 next/key 一起清掉 */
    free(p);
}

static void add_obj(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXSLOT) { puts("bad index"); return; }
    if (slots[i]) { puts("slot busy"); return; }
    printf("size: ");
    int sz = read_int();
    if (sz < 0x10 || sz > MAXSZ) { puts("bad size"); return; }
    char *p = malloc((size_t)sz);
    if (!p) { puts("oom"); return; }
    printf("data: ");
    if (read(0, p, (size_t)sz) != sz) exit(0);   /* 定长读，EXP 按 size 发字节 */
    slots[i] = p;                                 /* bug 2：del 之后这里不清空 */
    sizes[i] = (size_t)sz;
}

static void del_obj(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXSLOT || !slots[i]) { puts("no slot"); return; }
    secure_free(slots[i], sizes[i]);
    /* 不清空 slots[i] / sizes[i] → 可以重复 del + show 泄漏 */
    puts("done");
}

static void show_obj(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXSLOT || !slots[i]) { puts("no slot"); return; }
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
    puts("== lab_double_free ==");
    for (;;) {
        puts("1. add  2. show  3. del  4. trigger  5. exit");
        printf("choice: ");
        switch (read_int()) {
        case 1: add_obj();  break;
        case 2: show_obj(); break;
        case 3: del_obj();  break;
        case 4: trigger();  break;
        case 5: return 0;
        default: puts("??");
        }
    }
}
