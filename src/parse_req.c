/********************************************************************************
                                FILE HEADER
* NAME : parse_line.c

* DESCRIPTION : Contains function descriptions.

* DATE          AUTHOR          REFERENCE               PURPOSE

********************************************************************************/

#include<server.h>
/******************************************************************************
                                FUNCTION HEADER
* NAME : alarm_handler

* DESCRIPTION : Handler for SIGALRM

* RETURN : int

******************************************************************************/

static char *method[MAX_METHODS]={	"GET",
				"HEAD",
				"PUT",
				"POST"};
char *entity[]={"Allow",
		"Content-Encoding",
		"Content-Language",
		"Content-Length",
		"Content-Location",
		"Content-MD5",
		"Content-Range",
		"Content-Type",
		"Expires",
		"Last-Modified"};
char *gen[]=	{"Cache-Control",
		"Connection",
		"Date",
		"pragma",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"Via",
		"Warning"};
char *req[]=	{"Accept",
		"Accept-Charset",
		"Accept-Encoding",
		"Accept-Language",
		"Authorization",
		"Cookie",
		"Expect",
		"From",
		"Host",
		"If-Match",
		"If-Modified-Since",
		"If-None-Match",
		"If-Range",
		"If-Unmodified-Since",
		"Max-Forwards",
		"Proxy-Authorization",
		"Range","Referer",
		"TE",
		"User-Agent"};
char *res[]=	{"Accept-Ranges",
		"Age",
		"ETag",
		"Location",
		"Proxy-Authenticate",
		"Retry-After",
		"Server",
		"Set-Cookie",
		"Vary",
		"WWW-Authenticate"};
/******************************************************************************
                                FUNCTION HEADER
* NAME : parse_line

* DESCRIPTION : Parses a line till the eol is reached

* RETURN : int

******************************************************************************/

int parse_line(int socket,char line[MAX_FIELD_LEN])
{
int i = 0;
	memset(line,'\0',MAX_FIELD_LEN);
	printf("\nWaiting for request\n");
	while (TRUE && i < MAX_FIELD_LEN)
	{
		if (read(socket,&(line[i]),1) > 0)
		{
			i++;
		}
		if (i >= 1)
		{
			if (strstr(line,"\r\n") != NULL)
			{
				break;
			}
		}
	}
	printf("\nRequest received\n");

return SUCCESS;
}

void unencode(char *src, char *last, char *dest)
{
         for(; src != last; src++, dest++)
        {
                if(*src == '+')
                {
                        *dest = ' ';
                }
                else if(*src == '%')
                {
                        int code;
                        if(sscanf(src+1, "%2x", &code) != 1) code = '?';
                        *dest = code;
                        src +=2;
                }
                else
                {
                        *dest = *src;
                        *dest = '\n';
                        *++dest = '\0';
                }
        }
}
struct HTTP_REQUEST * parse_http_request(int socket,int *index)
{
	char req_h[REQ_H_CNT][MAX_FIELD_LEN];
	char gen_h[GEN_H_CNT][MAX_FIELD_LEN];
	char entity_h[ENTITY_H_CNT][MAX_FIELD_LEN];
	char req_line[MAX_METHODS][MAX_FIELD_LEN];
	int content_length = 0;
	char request[MAX_FIELD_LEN];
	char *ptr = NULL;
	int iter = 0;
	char resource[MAX_FIELD_LEN];
	char headers[MAX_FIELDS][MAX_FIELD_LEN];
	char *web_root = NULL;
	int field_count = 0;
	char requested[MAX_RCV_MSG_SIZE];
	int i = 0;
	struct HTTP_REQUEST 	*http_request = NULL;

	for (i = 0; i < MAX_METHODS; i++)	
	{
		strcpy(req_line[i],"");
	}
	memset(requested,'\0',MAX_RCV_MSG_SIZE);
	parse_line(socket,request);
	
	printf("\nrequest line %s\n",request);
	if (strlen(request) > 5)
	{
		ptr = strstr(request," HTTP/");
	}
        if (ptr == NULL)
        {
               	printf("NOT HTTP !\n");
		*ptr = '\0';
                ptr = NULL;
		return NULL;
        }
        else
        {
		
		strcpy(req_line[PROTOCOL], "HTTP");	//protocol
		ptr = ptr + 6;
		strcpy(req_line[VERSION] ,ptr);	//protocol version
		if (strlen(request) > 5)
		{
			ptr = strstr(request," HTTP/");
			if (ptr == NULL)
			{
				return NULL;
			}
			*ptr = '\0';
	                ptr = NULL;
		}
		for (iter = 0; iter < MAX_METHODS; iter++)
		{
	                if ((strlen(request) >= strlen(method[iter])) && strncmp(request, method[iter], strlen(method[iter])) == 0)
        	        {
				strcpy(req_line[METHOD] ,method[iter]);//method
	                        ptr = request + strlen(method[iter]) + 1;
				break;
        	        }
		}
		web_root = NULL;
		for (iter = 0; iter < MAX_METHODS; iter++)
		{
			web_root = strstr(req_line[METHOD],method[iter]); 
			if (web_root != NULL)
			{
				break;
			}
		}
		if (NULL == web_root)
		{
			printf("\nUnknown method\n");
			return NULL;
		}
		else
		{
			//printf("\nmethod %s\n",req_line[0]);
			memset(resource,'\0',MAX_FIELD_LEN);
			web_root = webroot();
                        strcpy(resource, web_root);
			free(web_root);
			strcat(resource,"/WEB");
	                strcat(resource, ptr);
			memset(requested,'\0',MAX_RCV_MSG_SIZE);
			unencode(resource,resource+strlen(resource),requested);
			strcpy(req_line[URL] ,resource);
		}
		memset(requested,'\0',MAX_RCV_MSG_SIZE);
		//printf("\nrequest line is parsed\n");
		read_fields(socket,requested);
		//printf("\nfields are read\n");
		for (i = 0; i < MAX_FIELDS; i++)	
		{
			strcpy(headers[i],"");
		}
		parse_fields(headers,requested,&field_count);	
		//printf("\nfields are paresed\n");
		ptr = NULL;
		for (i = 0;i < GEN_H_CNT;i++)
		{
			strcpy(gen_h[i],"\0");
		}
		for (i = 0;i < REQ_H_CNT;i++)
		{
			strcpy(req_h[i],"\0");
		}
		for (i = 0;i < ENTITY_H_CNT;i++)
		{
			strcpy(entity_h[i],"\0");
		}
		for (i = 0; iter <= field_count; iter++)
		{
			for (i = 0; i < GEN_H_CNT; i++)	
			{
				ptr = strstr(headers[iter],gen[i]);
				if (NULL != ptr)
				{
					strcpy(gen_h[i],(headers[iter] + strlen(gen[i]) + 1));
					break;
				}
			}
			if (NULL == ptr)
			{	
				for (i = 0; i < REQ_H_CNT; i++)	
				{
					ptr = strstr(headers[iter],req[i]);
					if (NULL != ptr)
					{
						strcpy(req_h[i],headers[iter] + strlen(req[i]) + 1);
						break;
					}
				}
			}
			if (NULL == ptr)
			{	
				for (i = 0; i < ENTITY_H_CNT; i++)	
				{
					ptr = strstr(headers[iter],entity[i]);
					if (NULL != ptr)
					{
						strcpy(entity_h[i] ,(headers[iter] + strlen(entity[i]) + 1));
						break;
					}
				}
			}
		}
	}
	http_request = http_request_packet(req_line,gen_h,req_h,entity_h);
	strcpy(http_request -> msg_body -> msg ,"\0");
	printf("\nreading message body\n");
	if (strstr(http_request -> req_fld -> pversion,"1.0") != NULL)
	{

		//printf("\nITs a HTTP 1.0 request\n");
		if ((http_request->entity_fld->content_len != NULL)&&((content_length = atoi(http_request -> entity_fld -> content_len)) > 0))
		{
			//printf("\ncontent length %d\n",content_length);
			if (http_request->request_fld->expect != NULL && strstr(http_request->request_fld->expect,"100-continue") != NULL)
			{
					
				send_new(socket, "HTTP/1.1 100 Continue\r\n");
				send_new(socket, SERVER"\r\n\r\n");
			}
				read_msg_body(socket,requested,content_length);
				//printf("\nrequest body %s\n",http_request->msg_body->msg);
				strcpy(http_request -> msg_body -> msg ,requested);
		}
		else
		{
			strcpy(http_request -> msg_body -> msg,"\0");
		}
	}
	else if (strstr(http_request -> req_fld -> pversion,"1.1") != NULL)
	{
		//printf("\nITs a HTTP 1.1 request\n");
		if (strstr(http_request->general_fld->transfercoding,"chunked")!=NULL)
		{
			read_chunked_msg(socket,requested);
                        strcpy(http_request -> msg_body -> msg,requested);
		}
		else if ((http_request->entity_fld->content_len != NULL)&&((content_length = atoi(http_request -> entity_fld -> content_len)) > 0))
		{
			//printf("\ncontent length %d\n",content_length);
			//read_msg_body(socket,requested,content_length);
			if (http_request->request_fld->expect != NULL && strstr(http_request->request_fld->expect,"100-continue") != NULL)
			{
					
				send_new(socket, "HTTP/1.1 100 Continue\r\n");
				send_new(socket, SERVER"\r\n\r\n");
			}
			read_msg_body(socket,requested,content_length);
			strcpy(http_request -> msg_body -> msg,requested);
		}
		else
		{
			strcpy(http_request -> msg_body -> msg,"\0");
		}
	}
	printf("\nMsg body is read\n");
return http_request;
}
