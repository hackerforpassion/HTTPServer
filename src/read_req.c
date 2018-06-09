#include<server.h>
void parse_fields(char destination[MAX_FIELDS][MAX_FIELD_LEN],char *start,int *field_count)
{
int count = 0;
char *temp = NULL;
char *tok = NULL;
	temp = strdup(start);
	//printf("\nfields \n %s\n",temp);
	tok = strtok(temp,"\r\n");
	while(tok != NULL)
	{
		//printf("\n%s\n",tok);
		strcpy(destination[count] ,tok);
		count++;
		tok = strtok(NULL,"\r\n");
	}
*field_count = count - 1;
free(temp);
}

int read_fields(int socket,char *requested)
{
	int i = 0;
	while (1)
	{
		read(socket,&(requested[i]),1);
		requested[i + 1] = '\0';
		if (i >= 3)
		{
			if (strstr(requested,"\r\n\r\n") != NULL)
			{
				break;
			}
		}
		i++;
	}
return (i-1);
}
int read_msg_body(int socket,char *requested,int len)
{
	memset(requested,'\0',MAX_RCV_MSG_SIZE);
	read(socket,requested,len);
return SUCCESS;
}
