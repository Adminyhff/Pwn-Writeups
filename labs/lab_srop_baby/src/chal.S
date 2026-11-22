/* lab_srop_baby —— 最小 SROP 靶场（自造，非真实赛题）
 *
 * 设计目标：只保留 SROP 必需的两样东西
 *   1) 一次可控的栈溢出（read 到 rsp）
 *   2) 两个 gadget：syscall; ret、pop rax; ret
 * NX 开启（GNU_STACK=RW），栈上 shellcode 不可执行，所以必须走 sigreturn。
 *
 * 交互：
 *   name:     read(0, bss_buf, 0x100)    -> 把 "/bin/sh\0" 放进已知 bss
 *   exploit:  read(0, rsp, 0x400)        -> 栈溢出，ret 取栈上返回地址
 *
 * 编译：as -o chal.o src/chal.S && ld -o chal chal.o
 */
    .section .text
    .global _start

_start:
    /* write(1, "name: ", 6) */
    mov     $1, %rax
    mov     $1, %rdi
    lea     msg1(%rip), %rsi
    mov     $6, %rdx
    syscall

    /* read(0, bss_buf, 0x100) */
    xor     %rax, %rax
    xor     %rdi, %rdi
    lea     bss_buf(%rip), %rsi
    mov     $0x100, %rdx
    syscall

    /* write(1, "exploit: ", 9) */
    mov     $1, %rax
    mov     $1, %rdi
    lea     msg2(%rip), %rsi
    mov     $9, %rdx
    syscall

    /* read(0, rsp, 0x400) —— 溢出点 */
    xor     %rax, %rax
    xor     %rdi, %rdi
    mov     %rsp, %rsi
    mov     $0x400, %rdx
    syscall

    /* 返回地址来自栈上，已被覆盖 */
    ret

/* ---- gadget 区（正常流程 ret 之后不会顺序执行到这里） ---- */

    .global gadget_syscall_ret
gadget_syscall_ret:
    syscall
    ret

    .global gadget_pop_rax_ret
gadget_pop_rax_ret:
    pop     %rax
    ret

    .section .rodata
msg1:
    .ascii "name: "
msg2:
    .ascii "exploit: "

    .section .bss
    .lcomm bss_buf, 0x100

/* 关键：显式声明"栈不需要可执行"。
 * 不写这一行 ld 不会生成 PT_GNU_STACK，老内核/内核对无该段的程序默认给可执行栈，
 * 那样就退化成 ret2shellcode，SROP 的目的就没了。 */
    .section .note.GNU-stack,"",@progbits
