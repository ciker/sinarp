#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <arpa/inet.h>

static void show()
{
	printf("I am sincoder");
}

int i = 1234;

void test()
{
	printf("I am test() in test.c\n");
}

int  main(int argc ,char ** argv)
{
	int ret;
	void (*s)();
	void *h;
	h = dlopen("a.so",RTLD_LAZY);
	if(h == NULL)
	{
		perror("dlopen():");
		return -1;
	}
	s = ((void  ( *)()) dlsym(h,"test"));
	if(s ==  NULL)
	{
		perror("xxx");
		return -1;
	}
	s();
	i =9922;
	s();
	printf("--->%d<--",i);
	return 0;
}

