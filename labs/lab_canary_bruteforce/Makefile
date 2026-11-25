# lab_canary_bruteforce —— 自造 canary 爆破靶场
#
#   make          # 生成 chal
#   make clean
#
# 必须保留 stack protector（canary）与 -no-pie（win 地址固定）；
# fork 循环写在程序里，因此不需要 socat，pwntools 直接 process() 就能复现。
#
# 注意：编译时 gcc 会报一条 `-Wstringop-overflow`（read 0x100 写进 char[0x40]）——
# 那条警告就是本题的漏洞本身，属预期，不要"修"掉。

CC     = gcc
CFLAGS = -O0 -g -fno-pie -no-pie -fstack-protector-strong -D_GNU_SOURCE -Wno-stringop-overflow

all: chal

chal: src/chal.c
	$(CC) $(CFLAGS) -o chal src/chal.c

clean:
	rm -f chal

.PHONY: all clean
