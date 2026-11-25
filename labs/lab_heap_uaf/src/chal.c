/* lab_heap_uaf —— 自造 heap UAF 靶场（amd64）：函数指针 UAF
 *
 * 结构对齐真实赛题（如 hitcontraining_uaf / hacknote）：
 *   struct note { char *data; void (*fn)(char *); };
 *   delete 只 free，不清空 notes[] → 已释放的结构体仍可被 show 调用。
 *
 * 预期利用：
 *   add(0x18) ×2 → free(0) → free(1)
 *   → add(0x18, p64(backdoor) + p64(0) + pad)：这次的 data chunk 正好落在
 *     旧的 note 结构体上，把 fn 改成 backdoor
 *   → show(1)：调用 stale 结构体里的 fn → backdoor
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXN  16
#define MAXSZ 0x100

struct note {
    char *data;
    void (*fn)(char *);
};

static struct note *notes[MAXN];
static size_t sizes[MAXN];

static void print_note(char *data) { printf("note: %s\n", data); }

static void backdoor(void) {
    puts("[+] stale fn called, here is your flag:");
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

static void add_note(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN) { puts("bad index"); return; }
    if (notes[i]) { puts("slot busy"); return; }
    printf("size: ");
    int sz = read_int();
    if (sz <= 0 || sz > MAXSZ) { puts("bad size"); return; }
    char *d = malloc((size_t)sz);            /* 先分配 data */
    if (!d) { puts("oom"); return; }
    printf("data: ");
    read(0, d, (size_t)sz);
    struct note *n = malloc(sizeof(struct note));   /* 再分配结构体 */
    if (!n) { puts("oom"); return; }
    n->data = d;
    n->fn = print_note;
    notes[i] = n;
    sizes[i] = (size_t)sz;
}

static void del_note(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !notes[i]) { puts("no note"); return; }
    free(notes[i]->data);
    free(notes[i]);
    /* 不清空 notes[i] → UAF */
    puts("done");
}

static void show_note(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !notes[i]) { puts("no note"); return; }
    notes[i]->fn(notes[i]->data);
}

static void edit_note(void) {
    printf("index: ");
    int i = read_int();
    if (i < 0 || i >= MAXN || !notes[i]) { puts("no note"); return; }
    printf("data: ");
    read(0, notes[i]->data, sizes[i]);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== lab_heap_uaf ==");
    for (;;) {
        puts("1. add  2. edit  3. free  4. show  5. exit");
        printf("choice: ");
        switch (read_int()) {
        case 1: add_note();  break;
        case 2: edit_note(); break;
        case 3: del_note();  break;
        case 4: show_note(); break;
        case 5: return 0;
        default: puts("??");
        }
    }
}
