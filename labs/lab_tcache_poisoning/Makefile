# lab_tcache_poisoning —— 自造 tcache poisoning 靶场
#
#   make          # 生成 chal
#   make clean
#
# 只用主机 gcc：需要 glibc >= 2.32（safe-linking）+ 2.34 之后没有 __free_hook，
# 这两点正是本题的设定；-no-pie 让 fh / backdoor 的地址可写死在 exp 里。

CC     = gcc
CFLAGS = -O0 -g -fno-pie -no-pie -fstack-protector-strong -D_GNU_SOURCE

all: chal

chal: src/chal.c
	$(CC) $(CFLAGS) -o chal src/chal.c

clean:
	rm -f chal

.PHONY: all clean
