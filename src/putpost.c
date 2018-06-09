#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#define SUCCESS 0
#define FAILURE 1
#define MAX_RCV_MSG_SIZE 8000
int main(int argc,char *argv[])
{
int socket = atoi(argv[4]);
char *msg = argv[3];
char *url = argv[2];
int method = atoi(argv[1]);
char buffer[MAX_RCV_MSG_SIZE];
char content_len[10];
	if(method == 3)
	{
			setenv("REQUEST_METHOD","PUT",1);
			setenv("SCRIPT_FILENAME",url,1);
			sprintf(content_len,"%d",strlen(msg) + 1);
			sprintf(buffer,"echo \"%s\" | ./post.cgi",msg);
			setenv("CONTENT_LENGTH",content_len,1);
			dup2(socket, STDOUT_FILENO);
			//printf("\n%s\n",buffer);
			system(buffer);
			exit(SUCCESS);
	}
	else if(method ==4)
	{
			setenv("REQUEST_METHOD","POST",1);
			setenv("SCRIPT_FILENAME",url,1);
			sprintf(content_len,"%d",strlen(msg) + 1);
			sprintf(buffer,"echo \"%s\" | ./post.cgi",msg);
			setenv("CONTENT_LENGTH",content_len,1);
			dup2(socket, STDOUT_FILENO);
			//printf("\n%s\n",buffer);
			system(buffer);
			exit(SUCCESS);
	}
exit(SUCCESS);
}
