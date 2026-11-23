/* loopback_unix_shim.c —— 环境兜底工具（非题目内容，不属于 exploit 本身）

背景
----
某些 WSL2 / 容器环境里，被测二进制自己 socket()->bind()->listen() 的 **loopback TCP**
连不通：内核里进程阻塞在 inet_csk_accept，而对端 SYN 却被 RST（`ss` / `/proc/net/tcp`
能看到 LISTEN，用 python -m http.server 或手写 C server 复现同样失败）。
这是宿主/沙箱的网络栈问题，不是二进制的问题。

做法
----
用 LD_PRELOAD 把 AF_INET + SOCK_STREAM 的监听 socket 改写成 AF_UNIX，
并让 socket() 返回的 fd 编号保持不变，于是服务端逻辑里
“3 = listen fd、4 = accept 出来的 client fd” 这些假设全部照旧，
栈溢出 / ROP / popen 反弹的利用代码一行都不用改。

构建
----
  gcc -shared -fPIC -O2 -o loopback_unix_shim.so loopback_unix_shim.c -ldl

使用（示例：jarvisoj_http）
----
  HTTP_UNIX=/tmp/http.sock LD_PRELOAD=/abs/path/loopback_unix_shim.so ./jarvisoj_http

  注意：LD_PRELOAD 以空格分隔多个库，路径里**不能有空格**。
  本仓库路径 "Pwn Writeups" 带空格，所以引用时用相对路径（cwd 里没有空格的部分），
  或先 cp 到 /tmp 再引用；否则 loader 静默跳过，表现为“连不上 HTTP_UNIX 的 socket”。

调试（可选，全部通过环境变量开启）
----
  SHIM_LOG=<file>   记录 fd>2 的 read()、popen()/fork()/execve()，并捕获致命信号打印 RIP
                    （崩溃现场里 pid / rip / rsp / 寄存器是定位 ROP 错位最快的手段）
*/
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <ucontext.h>
#include <unistd.h>

static void shim_logf(const char *fmt, ...) {
    const char *p = getenv("SHIM_LOG");
    if (!p) return;
    FILE *f = fopen(p, "a");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fclose(f);
}

/* ---------- 1. socket 家族重定向 ---------- */

static int (*r_socket)(int, int, int);
static int (*r_bind)(int, const struct sockaddr *, socklen_t);
static int (*r_listen)(int, int);
static int (*r_accept)(int, struct sockaddr *, socklen_t *);

static int inet_listen_fd = -1;

int socket(int domain, int type, int protocol) {
    if (!r_socket) r_socket = dlsym(RTLD_NEXT, "socket");
    if (domain == AF_INET && (type & 0xf) == SOCK_STREAM) {
        int fd = r_socket(AF_UNIX, type, 0);   /* 只要家族换成 AF_UNIX 就够 */
        if (fd >= 0) inet_listen_fd = fd;
        return fd;
    }
    return r_socket(domain, type, protocol);
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    if (!r_bind) r_bind = dlsym(RTLD_NEXT, "bind");
    if (fd == inet_listen_fd && addr && addr->sa_family == AF_INET) {
        const char *path = getenv("HTTP_UNIX");
        if (!path) path = "/tmp/loopback_unix_shim.sock";
        struct sockaddr_un un;
        memset(&un, 0, sizeof un);
        un.sun_family = AF_UNIX;
        strncpy(un.sun_path, path, sizeof un.sun_path - 1);
        unlink(un.sun_path);
        return r_bind(fd, (const struct sockaddr *)&un, sizeof un);
    }
    return r_bind(fd, addr, len);
}

int listen(int fd, int backlog) {
    if (!r_listen) r_listen = dlsym(RTLD_NEXT, "listen");
    if (fd == inet_listen_fd) backlog = 16;
    return r_listen(fd, backlog);
}

int accept(int fd, struct sockaddr *addr, socklen_t *len) {
    if (!r_accept) r_accept = dlsym(RTLD_NEXT, "accept");
    if (fd == inet_listen_fd) return r_accept(fd, NULL, NULL);
    return r_accept(fd, addr, len);
}

/* ---------- 2. 调试探针（仅在 SHIM_LOG 存在时生效） ---------- */

static void crash_handler(int sig, siginfo_t *si, void *uc) {
    ucontext_t *u = (ucontext_t *)uc;
    shim_logf("CRASH pid=%d sig=%d rip=%p addr=%p rsp=%p rbp=%p rax=%p rbx=%p "
              "r12=%p r13=%p r14=%p r15=%p\n",
              getpid(), sig, (void *)u->uc_mcontext.gregs[REG_RIP], si->si_addr,
              (void *)u->uc_mcontext.gregs[REG_RSP], (void *)u->uc_mcontext.gregs[REG_RBP],
              (void *)u->uc_mcontext.gregs[REG_RAX], (void *)u->uc_mcontext.gregs[REG_RBX],
              (void *)u->uc_mcontext.gregs[REG_R12], (void *)u->uc_mcontext.gregs[REG_R13],
              (void *)u->uc_mcontext.gregs[REG_R14], (void *)u->uc_mcontext.gregs[REG_R15]);
    _exit(99);
}

__attribute__((constructor)) static void shim_init(void) {
    if (!getenv("SHIM_LOG")) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}

static ssize_t (*r_read)(int, void *, size_t);

ssize_t read(int fd, void *buf, size_t n) {
    if (!r_read) r_read = dlsym(RTLD_NEXT, "read");
    ssize_t ret = r_read(fd, buf, n);
    if (fd > 2 && getenv("SHIM_LOG")) {
        shim_logf("pid=%d fd=%d n=%zu ret=%zd%s", getpid(), fd, n, ret,
                  ret == 1 ? "" : "\n");
        if (ret == 1) shim_logf(" b=%02x\n", *(unsigned char *)buf);
    }
    return ret;
}

FILE *popen(const char *cmd, const char *mode) {
    static FILE *(*r_popen)(const char *, const char *);
    if (!r_popen) r_popen = dlsym(RTLD_NEXT, "popen");
    shim_logf("POPEN pid=%d cmd=%s mode=%s\n", getpid(), cmd ? cmd : "(null)",
              mode ? mode : "(null)");
    FILE *f = r_popen(cmd, mode);
    shim_logf("POPEN ret pid=%d f=%p\n", getpid(), (void *)f);
    return f;
}

pid_t fork(void) {
    static pid_t (*r_fork)(void);
    if (!r_fork) r_fork = dlsym(RTLD_NEXT, "fork");
    pid_t p = r_fork();
    shim_logf("FORK pid=%d -> %d\n", getpid(), (int)p);
    return p;
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    static int (*r_execve)(const char *, char *const[], char *const[]);
    if (!r_execve) r_execve = dlsym(RTLD_NEXT, "execve");
    shim_logf("EXECVE pid=%d path=%s\n", getpid(), path ? path : "(null)");
    return r_execve(path, argv, envp);
}
