#include<server.h>


//Possible media types

static extn extensions[] ={
        {"gif", "image/gif" },
        {"txt", "text/plain" },
        {"jpg", "image/jpg" },
        {"jpeg","image/jpeg"},
        {"png", "image/png" },
        {"ico", "image/ico" },
        {"zip", "image/zip" },
        {"gz",  "image/gz"  },
        {"tar", "image/tar" },
        {"htm", "text/html" },
        {"html","text/html" },
        {"php", "text/html" },
        {"pdf","application/pdf"},
        {"zip","application/octet-stream"},
        {"rar","application/octet-stream"},
	{"js","text/javascript"},
	{"tiff","image/tif"},
	{"c","text/plain"},
	{"cpp","text/plain"},
	{"java","text/plain"},
	{"jsp","text/plain"},
{0,0} };

int send_media_file(int fd,char *resource,int media_type)
{
        char * s = NULL;
        int fd1 = -1;
        int i = 0;
        int method = 1;
        size_t total_bytes_sent = 0;
        ssize_t bytes_sent = 0;
	int attempt = 0;
        int length = 0;
	char buffer[MAX_BUFF];
	memset(buffer,'\0',MAX_BUFF);
                if(NULL != resource)
                {
                        s = strchr(resource,'.');

                        for (i = 0; extensions[i].ext != NULL; i++)
                        {
                                if (strcmp(s + 1, extensions[i].ext) == 0)
                                {
                                        fd1 = open(resource, O_RDONLY, 0);
                                        printf("Opening \"%s\"\n", resource);
                                        if (fd1 == -1)
                                        {
                                                printf("404 File not found Error\n");
                                                send_new(fd, "HTTP/1.1 404 Not Found\r\n");
                                                send_new(fd, "Server : RAMESHHTTP\r\n\r\n");
                                                send_new(fd, "<html><head><title>404 Not Found</head></title>");
                                                send_new(fd, "<body><p>404 Not Found: The requested resource could not be found!</p></body></html> ");
                                                return FAILURE;
                                        }
                                        else
                                        {
                                               
                        			if ((length = get_file_size(fd1)) == -1)
			                        {
			                        	printf("Error in getting size !\n");
                        			}
						printf("200 OK, Content-Type: %s \r\n ",extensions[i].mediatype);
                                                send_new(fd, "HTTP/1.1 200 OK \r\n ");
						send_new(fd,"Accept-Ranges: Bytes \r\n ");
                                                send_new(fd, "Server: RAMESHHTTP \r\n ");
						if (media_type == DOWNLOAD)
						{
							sprintf(buffer,"Content-Disposition: attachment \r\n filename= %s\r\n",resource);	
							send_new(fd, buffer);
						}
						sprintf(buffer,"Content-Length: %d \r\n ",length);
						send_new(fd, buffer);
                                                sprintf(buffer,"Content-Type: %s \r\n\r\n ",extensions[i].mediatype);
						send_new(fd, buffer);
                                                if (method == 1) // if it is a GET request
                                                {
                                                        while (total_bytes_sent < length && attempt < 10)
                                                        {
                                                        //Zero copy optimization
								attempt++;;
                                                                if ((bytes_sent = sendfile(fd, fd1, 0,length - total_bytes_sent)) <= 0)
                                                                {
                                                                        if (errno == EINTR || errno == EAGAIN)
                                                                        {
                                                                                continue;
                                                                        }
                                                                        perror("sendfile");

                                                                        return -1;
                                                                }
                                                                total_bytes_sent += bytes_sent;
                                                        }
                                                }
                                        }
                                        break;
                                }
                                int size = sizeof(extensions) / sizeof(extensions[0]);
                                if (i == size - 2)
                                {
                                        printf("415 Unsupported Media Type\n");
                                        send_new(fd, "HTTP/1.1 415 Unsupported Media Type\r\n");
                                        send_new(fd, "Server : RAMESHHTTP\r\n\r\n");
                                        send_new(fd, "<html><head><title>415 Unsupported Media Type</head></title> ");
                                        send_new(fd, "<body><p>415 Unsupported Media Type!</p></body></html> ");
                                }
                        }
                }
return SUCCESS;
}
