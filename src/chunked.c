#include<server.h>
int read_chunked_msg(int socket,char msg[MAX_RCV_MSG_SIZE])
{
int read_bytes = 0;
int length = 0;
char line[MAX_FIELD_LEN];
int cur_chunk = 0;
	memset(msg,'\0',MAX_RCV_MSG_SIZE);
	while (read_bytes < MAX_RCV_MSG_SIZE)
	{
			parse_line(socket,line);
			sscanf(line,"%x",&length);
			if (length == 0)
			{
				break;
			}
			memset(line,'\0',MAX_FIELD_LEN);
			cur_chunk = 0;
			while (cur_chunk < length)
			{
				cur_chunk += read(socket,line,length);
				strcat(msg,line);
			}
			read_bytes += cur_chunk;
			parse_line(socket,line);
	}
return SUCCESS;
}

