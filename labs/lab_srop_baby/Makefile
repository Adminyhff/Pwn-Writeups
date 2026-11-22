# lab_srop_baby —— 自造 SROP 靶场
#
#   make          # 生成 chal
#   make clean
#
# 只用 binutils：as + ld，不依赖 libc / crt，任何 x86_64 Linux 都能复现。

AS  = as
LD  = ld
OBJ = chal.o

all: chal

chal: src/chal.S
	$(AS) -o $(OBJ) src/chal.S
	$(LD) -o chal $(OBJ)
	rm -f $(OBJ)

clean:
	rm -f chal $(OBJ)

.PHONY: all clean
