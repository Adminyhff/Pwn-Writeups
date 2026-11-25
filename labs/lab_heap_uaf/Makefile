# lab_heap_uaf —— 自造 heap UAF 靶场（函数指针 UAF）
#
#   make          # 生成 chal
#   make clean
#
# -no-pie：backdoor 地址固定，exp 里可以直接用符号；
# tcache 复用顺序（同 size class 的 LIFO）是本 lab 的核心，别加 -O2。

CC     = gcc
CFLAGS = -O0 -g -fno-pie -no-pie -fstack-protector-strong -D_GNU_SOURCE

all: chal

chal: src/chal.c
	$(CC) $(CFLAGS) -o chal src/chal.c

clean:
	rm -f chal

.PHONY: all clean
