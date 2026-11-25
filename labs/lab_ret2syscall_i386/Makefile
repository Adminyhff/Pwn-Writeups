# lab_ret2syscall_i386 —— 自造 ret2syscall 靶场
#
#   make          # 生成 chal
#   make clean
#
# 只用 binutils：as --32 + ld -m elf_i386，不依赖 libc / crt，任何 i386 Linux 都能复现。
# 需要系统装了 32 位 binutils 支持（gcc-multilib 不必装，as/ld 自带 --32 / elf_i386）。

AS  = as
LD  = ld
OBJ = chal.o

all: chal

chal: src/chal.S
	$(AS) --32 -o $(OBJ) src/chal.S
	$(LD) -m elf_i386 -o chal $(OBJ)
	rm -f $(OBJ)

clean:
	rm -f chal $(OBJ)

.PHONY: all clean
