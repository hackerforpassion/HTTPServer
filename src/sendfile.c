#include<server.h>
int send_file(int fd,char *requested)
{
int total_bytes_sent = 0;
int bytes_sent = 0;
int length = 0;
int attempt = 0;
	int fd1 = open(requested, O_RDONLY, 0);
	if (fd1 == 1)
	{
		printf("\nError sending data to client\n");
		return FAILURE;
	}
	length = get_file_size(fd1);
	while (total_bytes_sent < length && attempt < MAX_ATTEMPTS) 
	{
		//Zero copy optimization
		attempt++;
		if ((bytes_sent = sendfile(fd, fd1, 0,length - total_bytes_sent)) <= 0) 
		{
			if (errno == EINTR || errno == EAGAIN) 
			{
				continue;
			}
									
		}
		total_bytes_sent += bytes_sent;
	}
return SUCCESS;
}

