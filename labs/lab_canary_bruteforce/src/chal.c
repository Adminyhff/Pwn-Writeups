/* lab_canary_bruteforce —— 自造「canary 逐字节爆破」靶场（amd64）
 *
 * 教学点：
 *   1) 每次连接由父进程 fork 出新子进程 → 子进程继承同一个 canary，
 *      于是可以逐字节试错（最多 256 次/字节），这就是真实赛题的 "fork server" 模型；
 *   2) 判断依据不是“有没有输出”，而是 __stack_chk_fail 打印的
 *      "*** stack smashing detected ***" 与正常返回后打印的 "SURVIVED" 的区别；
 *   3) 末字节注意：x86-64 的 canary 最低字节恒为 \x00。
 *
 * 预期利用：0x48 字节填充 + 8 字节 canary + 8 字节 saved rbp + win 地址。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static void win(void) {
    puts("[+] canary bypassed, here is your flag:");
    system("cat flag.txt");
}

static void vuln(void) {
    char buf[0x40];
    memset(buf, 0, sizeof(buf));
    write(1, "payload: ", 9);
    if (read(0, buf, 0x100) <= 0) _exit(0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== lab_canary_bruteforce ==");
    for (;;) {
        pid_t pid = fork();
        if (pid == 0) {
            vuln();                 /* canary 校验发生在函数返回时 */
            puts("SURVIVED");       /* 只有校验通过才走得到这里 */
            _exit(0);
        }
        if (pid < 0) return 1;
        int st;
        waitpid(pid, &st, 0);
    }
}
