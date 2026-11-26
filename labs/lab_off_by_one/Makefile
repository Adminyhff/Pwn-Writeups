# lab_off_by_one —— 自造 off-by-one（chunk overlap）靶场
#
#   make          # 生成 chal
#   make clean
#
# 只用主机 gcc：需要 safe-linking（glibc >= 2.32）与“2.34 之后没有 __free_hook”，
# 这两点正是本题设定；劫持目标因此是 .bss 里的函数指针表。
# -no-pie 让 handlers / win 的地址可写死在 exp 里。

CC     = gcc
CFLAGS = -O0 -g -fno-pie -no-pie -fstack-protector-strong -D_GNU_SOURCE

all: chal

chal: src/chal.c
	$(CC) $(CFLAGS) -o chal src/chal.c

clean:
	rm -f chal

.PHONY: all clean
