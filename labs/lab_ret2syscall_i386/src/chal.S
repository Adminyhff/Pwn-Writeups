/* lab_ret2syscall_i386 —— 最小 ret2syscall 靶场（自造，非真实赛题）
 *
 * 设计目标：只保留"纯 syscall ROP"必需的东西
 *   1) 一次可控的栈溢出（read 到 esp）
 *   2) 一组 pop reg; ret + int 0x80; ret gadget
 * 没有 libc、没有 system、没有 /bin/sh 字符串 —— 想要 shell 只能自己用
 * read(0, bss, 8) 把 "/bin/sh" 写进 bss，再 execve(bss, 0, 0)。
 *
 * 交互：
 *   name:     read(0, bss_buf, 8)        -> 固定 8 字节，"bin/sh\0" 正好放得下
 *   exploit:  read(0, esp, 0x400)        -> 栈溢出，ret 直接取 [esp]
 *
 * 编译：as --32 -o chal.o src/chal.S && ld -m elf_i386 -o chal chal.o
 */
    .section .text
    .global _start

_start:
    /* write(1, "name: ", 6) */
    mov     $4, %eax
    mov     $1, %ebx
    mov     $msg1, %ecx
    mov     $6, %edx
    int     $0x80

    /* read(0, bss_buf, 8) —— i386 里 read = 3（0 是 restart_syscall，会返回 -EINTR）*/
    mov     $3, %eax
    xor     %ebx, %ebx
    mov     $bss_buf, %ecx
    mov     $8, %edx
    int     $0x80

    /* write(1, "exploit: ", 9) */
    mov     $4, %eax
    mov     $1, %ebx
    mov     $msg2, %ecx
    mov     $9, %edx
    int     $0x80

    /* read(0, esp, 0x400) —— 溢出点，数据直接落在当前栈顶 */
    mov     $3, %eax
    xor     %ebx, %ebx
    mov     %esp, %ecx
    mov     $0x400, %edx
    int     $0x80

    /* 返回地址来自栈上，已被覆盖：eax=3 的剩余返回值不影响 ret */
    ret

/* ---- gadget 区（正常流程 ret 之后不会顺序执行到这里）---- */

    .global gadget_int80_ret
gadget_int80_ret:
    int     $0x80
    ret

    .global gadget_pop_eax_ret
gadget_pop_eax_ret:
    pop     %eax
    ret

    .global gadget_pop_ebx_ret
gadget_pop_ebx_ret:
    pop     %ebx
    ret

    .global gadget_pop_ecx_ret
gadget_pop_ecx_ret:
    pop     %ecx
    ret

    .global gadget_pop_edx_ret
gadget_pop_edx_ret:
    pop     %edx
    ret

    .section .rodata
msg1:
    .ascii "name: "
msg2:
    .ascii "exploit: "

    .section .data
    .balign 16
bss_buf:
    .zero 0x100

/* 显式声明栈不可执行（PT_GNU_STACK=RW），否则就退化成 ret2shellcode。 */
    .section .note.GNU-stack,"",@progbits
