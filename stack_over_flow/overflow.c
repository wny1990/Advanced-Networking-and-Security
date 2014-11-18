#include<stdio.h>
#include<string.h>
void auth(char* src)
{
	char dst[0];
	strcpy(dst,src);
	return;
}
void hack()
{
	printf("miao! miao! miao!\n");
	printf("The big cat has stolen your fish!\n");
	while(1);
	return;
}
int main()
{
	printf("address of hack:%p\n",hack);
	char* src = "aaaaaaaaaaaa\xc8\x84\x04\x08";
	auth(src);
	return 0;
}
