#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#define SUCCESS 0
#define FAILURE 1
int main(int argc,char*argv[])
{
	char * query = argv[1];
	int socket = atoi(argv[2]);
	//printf("\n%s\n",query);
	dup2(socket, STDOUT_FILENO);
	system(query);
exit(SUCCESS);
}
