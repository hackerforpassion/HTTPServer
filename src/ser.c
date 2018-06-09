#include<stdio.h> 
#include<string.h> //strlen 
#include<sys/socket.h> 
#include<arpa/inet.h> //inet_addr 
#include<unistd.h> //write 
#include<stdlib.h>
#include<pthread.h>
#include<signal.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<time.h>
#include<errno.h>
#include<sys/shm.h>
#include<sys/wait.h>
#include<sys/sendfile.h>
#define SUCCESS 0
#define FAILURE 1
#define FILE_ERROR -1
#define MAX_BUFF 1024
#define MAX_PROCESSES 10
#define RUN_SERVER 1
#define STOP_SERVER 2
#define EXIT_MONITOR 3
#define EXIT_ADMIN 4
#define ERROR -1
#ifndef HTTP_STATUS_CODES

#define HTTP_STATUS_CODES

#define HTTP_OK 200
#define HTTP_NAUTH 203
#define HTTP_NOCONTENT 204
#define HTTP_ACCEPTED 202
#define HTTP_CREATED 201
#define HTTP_RST 205
#define HTTP_PART 206
#define HTTP_MULTISTAUTS 207
#define CONTINUE 100
#define CACHE 1
#define KEEP_ALIVE 1
#define EXPIRES 10
#define MAX_CACHE_AGE "max-age=100"
#endif

#define MAX_METHODS 4
#define MAX_FIELD_LEN 500
#define MAX_FIELDS 100
#define MAX_RCV_MSG_SIZE 8000
#define EOL "\r\n"

#define EOL_SIZE 2
#define ENV_CNT 1000
#define ENV_LEN 100

#define GEN_H_CNT 9
#define ENTITY_H_CNT 10
#define REQ_H_CNT 20
#define RES_H_CNT 10
#define GET 1
#define HEAD 2
#define PUT 3
#define POST 4
#define DOWNLOAD 1
#define DISPLAY 2
#define TIMER 10
#define MAX_ATTEMPTS 5
#define METHOD 0
#define URL 1
#define PROTOCOL 2
#define VERSION 3
#define TRUE 1
#define FALSE 0
#define NOTFOUND "404 NOTFOUND"
#define OK "200 OK"
#define SERVER "Server: RAMESHHTTP/1.1"
#define TIMER_CONNECT 3
int exit_server = 0;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
int thread_count = 0;
int socket_desc = 0; 
unsigned int log_count = 0;
/*-------------------------------------------------*/
typedef struct HTTP_RESPONSE_PACKET
{
	char *status_line;
	char *general_header;
	char *response_header;
	char *entity_header;
	char *msg_body;
	char *msg_trailer;
}http_response_packet;
typedef struct HTTP_REQ_PACKET
{
	char *request_line;
	char *general_header;
	char *request_header;
	char *entity_header;
	char *msg_body;
	char *msg_trailer;
}http_req_packet;


struct http_gen_header
{
	char cache_control[MAX_FIELD_LEN];
	char connection[MAX_FIELD_LEN];
	char date[MAX_FIELD_LEN];
	char pragma[MAX_FIELD_LEN];
	char trailer[MAX_FIELD_LEN];
	char transfercoding[MAX_FIELD_LEN];
	char upgrade[MAX_FIELD_LEN];
	char via[MAX_FIELD_LEN];
	char warning[MAX_FIELD_LEN];
};
struct http_client_req
{
	char accept[MAX_FIELD_LEN];
	char acc_chr_set[MAX_FIELD_LEN];;
	char acc_encode[MAX_FIELD_LEN];
	char acc_lang[MAX_FIELD_LEN];
	char authorize[MAX_FIELD_LEN];
	char cookie[MAX_FIELD_LEN];
	char expect[MAX_FIELD_LEN];
	char from[MAX_FIELD_LEN];
	char host[MAX_FIELD_LEN];
	char if_match[MAX_FIELD_LEN];
	char if_mod_snc[MAX_FIELD_LEN];
	char if_none_mtch[MAX_FIELD_LEN];
	char if_range[MAX_FIELD_LEN];
	char if_unmod_snc[MAX_FIELD_LEN];
	char max_fwd[MAX_FIELD_LEN];
	char proxy_auth[MAX_FIELD_LEN];
	char range[MAX_FIELD_LEN];
	char referer[MAX_FIELD_LEN];
	char te[MAX_FIELD_LEN];
	char uagent[MAX_FIELD_LEN];
};
struct http_srv_res
{
	char accept_ranges[MAX_FIELD_LEN];
	char age[MAX_FIELD_LEN];
	char etag[MAX_FIELD_LEN];
	char location[MAX_FIELD_LEN];
	char proxy_auth[MAX_FIELD_LEN];
	char retry_after[MAX_FIELD_LEN];
	char server[MAX_FIELD_LEN];
	char set_cookie[MAX_FIELD_LEN];
	char vary[MAX_FIELD_LEN];
	char www_auth[MAX_FIELD_LEN];
};
struct entity_header
{
	char allow[MAX_FIELD_LEN];
	char content_encode[MAX_FIELD_LEN];
	char content_lang[MAX_FIELD_LEN];
	char content_len[MAX_FIELD_LEN];
	char content_loc[MAX_FIELD_LEN];
	char content_md5[MAX_FIELD_LEN];
	char content_range[MAX_FIELD_LEN];
	char content_type[MAX_FIELD_LEN];
	char expires[MAX_FIELD_LEN];
	char last_mod[MAX_FIELD_LEN];
};


struct http_req
{
	char  method[MAX_FIELD_LEN];
	char  url[MAX_FIELD_LEN];
	char  protocol[MAX_FIELD_LEN];
	char  pversion[MAX_FIELD_LEN];
};
struct msg
{
	char msg[MAX_RCV_MSG_SIZE];
};
struct HTTP_REQUEST
{
	struct http_req 	*req_fld;
	struct http_gen_header 	*general_fld;
	struct http_client_req 	*request_fld; 
	struct entity_header 	*entity_fld;
	struct msg 		*msg_body;
	char 			*msg_trailer;
};
struct http_status
{
	char protocol[MAX_FIELD_LEN];
	char version[MAX_FIELD_LEN];
	char  status[MAX_FIELD_LEN];
};
struct HTTP_RESPONSE
{
	struct http_status 	*status_line;
	struct http_gen_header 	*general_header;
	struct http_srv_res *response_line;
	struct entity_header 	*entity_header_fld;
	struct msg 		*msg_body;
	char 			* msg_trailer;
};
typedef struct {
        char *ext;
        char *mediatype;
} extn;



//Possible media types

extn extensions[] ={
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
char *method[MAX_METHODS]={	"GET",
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
int get_date(char *file,char *buffer)
{
	struct stat buf;
	struct tm *mtime;
	stat(file,&buf);
	mtime = gmtime(&(buf.st_mtime));
	sprintf(buffer,"Last modified %u/%u/%u; %u:%u",(mtime->tm_year) + 1900,(mtime->tm_mon) + 1,mtime->tm_mday,mtime->tm_hour,mtime->tm_min);
	return 0;
}
int get_date(char *file,char *buffer);
void send_new(int fd, char *msg);
int find_method(char *request);
int send_http_response_pack(int new_socket,http_response_packet * http_res,int method);
char* webroot();
int parse_line(int socket,int *keep_alive,char line[MAX_FIELD_LEN]);
void unencode(char *src, char *last, char *dest);
void parse_fields(char destination[MAX_FIELDS][MAX_FIELD_LEN],char *start,int *field_count);
struct HTTP_RESPONSE * HTTP_response_packet();
void strcopy(char *destination,char *source);
struct HTTP_REQUEST * http_request_packet(char req_line[MAX_METHODS][MAX_FIELD_LEN],char gen_h[GEN_H_CNT][MAX_FIELD_LEN],char req_h[REQ_H_CNT][MAX_FIELD_LEN],char entity_h[ENTITY_H_CNT][MAX_FIELD_LEN]);
void free_it(void **ptr);
void free_http_packets(struct HTTP_REQUEST **http_request,struct HTTP_RESPONSE **http_response);
int read_fields(int socket,char *requested);
int read_msg_body(int socket,char *requested,int len);
void print_data(FILE *fp,char *field,char * value);
void print_http_response(struct HTTP_RESPONSE *http_response,FILE *fp);
void print_http_request(struct HTTP_REQUEST *http_request,FILE *fp);
int read_chunked_msg(int socket,char msg[MAX_RCV_MSG_SIZE],int *processing);
struct HTTP_REQUEST * parse_http_request(int socket,int *index,int *keep_alive);
int last_modified(char *requested,char *time);
int retrieve_page_info(struct HTTP_REQUEST *request,struct HTTP_RESPONSE *response);
void add_field(char **destination,char *source);
void create_http_response_msg(http_response_packet *http_res,struct HTTP_RESPONSE *response);
int create_http_head_response_pack(struct HTTP_REQUEST *request,struct HTTP_RESPONSE *response,http_response_packet *http_res);
int create_http_response_pack(http_response_packet *http_res,struct HTTP_REQUEST *request,struct HTTP_RESPONSE **response);
int update_log(char *log_file,const char *log);
int read_line(int fd,char *message);
int is_phppage(char *requested);
int is_htmlpage(char *requested);
void call_php(struct HTTP_REQUEST *request,char *php_path,int socket);
int get_file_size(int fd);
void replace(char *s, char old, char new);
int send_file(int fd,char *requested);
int peer_addr(int s, char *buf, int bufsiz);
int send_media_file(int fd,char *resource,int media_type);
int encode_msg(char *msg);
int serve(int socket,http_response_packet *http_res,char *log);
struct tm*get_current_time();
void *serve_client(void* new_socket);
void send_new(int fd, char *msg) 
{
	int len = strlen(msg);
	if (send(fd, msg, len - 1, 0) == -1) 
	{
		printf("Error in send\n");
	}
}
int find_method(char *request)
{
	int meth = -1;
	int index = 0;
	for(index = 0; index < MAX_METHODS; index++)
	{
		if(request != NULL && strlen(request) >= strlen(method[index])&&(0 == strcmp(request,method[index])))
		{
			meth = index + 1;
			break;
		}
	}
return meth;
}
int send_http_response_pack(int new_socket,http_response_packet * http_res,int method)
{
	char buffer[MAX_RCV_MSG_SIZE];
	memset(buffer,'\0',MAX_RCV_MSG_SIZE);
	switch(method)
	{
	case 1:
		sprintf(buffer,"%s%s%s%s\r\n\r\n",http_res->status_line,http_res->general_header,http_res->response_header,http_res->entity_header);
		break;
	case 2:
		sprintf(buffer,"%s%s\r\n",http_res->status_line,http_res->response_header);
		break;
	default:
		return FAILURE;
	}
	send_new(new_socket,buffer);
return SUCCESS;
}
char* webroot()
{
// open the file "conf" for reading

        FILE *in = fopen("conf","r+");

// read the first line from the file
        char buff[MAX_BUFF];
        fgets(buff,MAX_BUFF , in);
// close the stream
        fclose(in);
        char* nl_ptr = strrchr(buff, '\n');
        if (nl_ptr != NULL)
        *nl_ptr = '\0';
        return strdup(buff);
}

int parse_line(int socket,int *keep_alive,char line[MAX_FIELD_LEN])
{
int i = 0;
	memset(line,'\0',MAX_FIELD_LEN);
	printf("\nWaiting for request\n");
	void alarm_h()
	{
		*keep_alive = 0;
		pthread_exit(NULL);
		pthread_detach(pthread_self());
	}
	alarm(TIMER_CONNECT);
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
struct HTTP_RESPONSE * HTTP_response_packet()
{
	struct HTTP_RESPONSE *http_response;

	struct http_status 		*status_line = NULL;
	struct http_gen_header 		*gen_header = NULL;
	struct http_srv_res 	*response_header = NULL;
	struct entity_header 		*entity_header_fld = NULL;
	struct msg 			*msg_body = NULL;
	http_response = (struct HTTP_RESPONSE*)malloc(sizeof(struct HTTP_RESPONSE));

	status_line = (struct http_status*)malloc(sizeof(struct http_status));
	gen_header = (struct http_gen_header*)malloc(sizeof(struct http_gen_header));
	response_header = (struct http_srv_res*)malloc(sizeof(struct http_srv_res));
	entity_header_fld = (struct entity_header*)malloc(sizeof(struct entity_header));
	msg_body = (struct msg*)malloc(sizeof(struct msg));

	strcpy(status_line -> protocol , "\0");
	strcpy(status_line -> version , "\0");
	strcpy(status_line -> status , "\0");
	
	strcpy(gen_header -> cache_control , "\0");
	strcpy(gen_header -> connection , "\0");
	strcpy(gen_header -> date , "\0");
	strcpy(gen_header -> pragma , "\0");
	strcpy(gen_header -> trailer , "\0");
	strcpy(gen_header -> transfercoding , "\0");
	strcpy(gen_header -> upgrade ,"\0");
	strcpy(gen_header -> via , "\0");
	strcpy(gen_header -> warning , "\0");
	
	strcpy(response_header -> accept_ranges , "\0");
	strcpy(response_header -> age , "\0");
	strcpy(response_header -> etag , "\0");
	strcpy(response_header -> location , "\0");
	strcpy(response_header -> proxy_auth , "\0");
	strcpy(response_header -> retry_after , "\0");
	strcpy(response_header -> server , "\0");
	strcpy(response_header -> set_cookie , "\0");
	strcpy(response_header -> vary , "\0");
	strcpy(response_header -> www_auth , "\0");

	strcpy(entity_header_fld -> allow , "\0");
	strcpy(entity_header_fld -> content_encode , "\0");	
	strcpy(entity_header_fld -> content_lang , "\0");	
	strcpy(entity_header_fld -> content_len , "\0");
	strcpy(entity_header_fld -> content_loc , "\0");
	strcpy(entity_header_fld -> content_md5 , "\0");
	strcpy(entity_header_fld -> content_range , "\0");
	strcpy(entity_header_fld -> content_type , "\0");
	strcpy(entity_header_fld -> expires , "\0");
	strcpy(entity_header_fld -> last_mod , "\0");
	strcpy(msg_body -> msg ,"\0");
	
	http_response -> status_line = status_line;
	http_response -> general_header = gen_header;
	http_response -> response_line = response_header;
	http_response -> entity_header_fld = entity_header_fld;
	http_response -> msg_body = msg_body;
	http_response -> msg_trailer = strdup("\0");

return http_response;

}
void strcopy(char *destination,char *source)
{
	if (strlen(source) > 0)
	{
		strcpy(destination,source);
	}
	else
	{
		strcpy(destination,"\0");
	}
}
struct HTTP_REQUEST * http_request_packet(char req_line[MAX_METHODS][MAX_FIELD_LEN],char gen_h[GEN_H_CNT][MAX_FIELD_LEN],char req_h[REQ_H_CNT][MAX_FIELD_LEN],char entity_h[ENTITY_H_CNT][MAX_FIELD_LEN])
{
	struct HTTP_REQUEST 	*http_request;

	struct http_req 	*request_line;
	struct http_gen_header 	*gen_header;
	struct http_client_req 	*request_header;
	struct entity_header 	*entity_header_fld;
	struct msg 		*msg_body;
	http_request = (struct HTTP_REQUEST*)malloc(sizeof(struct HTTP_REQUEST));
	request_line = (struct http_req*)malloc(sizeof(struct http_req));
	gen_header = (struct http_gen_header*)malloc(sizeof(struct http_gen_header));
	request_header = (struct http_client_req*)malloc(sizeof(struct http_client_req));
	entity_header_fld = (struct entity_header*)malloc(sizeof(struct entity_header));
	msg_body = (struct msg*)malloc(sizeof(struct msg));

	strcopy(request_line -> method ,req_line[0]);
	strcopy(request_line -> url ,req_line[1]);
	strcopy(request_line ->protocol ,req_line[2]);
	strcopy(request_line ->pversion , req_line[3]);
	
	strcopy(gen_header -> cache_control , gen_h[0]);
	strcopy(gen_header -> connection , gen_h[1]);
	strcopy(gen_header -> date ,gen_h[2]);
	strcopy(gen_header -> pragma , gen_h[3]);
	strcopy(gen_header -> trailer , gen_h[4]);
	strcopy(gen_header -> transfercoding , gen_h[5]);
	strcopy(gen_header -> upgrade, gen_h[6]);
	strcopy(gen_header -> via ,gen_h[7]);
	strcopy(gen_header -> warning , gen_h[8]);

	strcopy(request_header -> accept , req_h[0]);
	strcopy(request_header -> acc_chr_set , req_h[1]);
	strcopy(request_header -> acc_encode , req_h[2]);
	strcopy(request_header -> acc_lang , req_h[3]);
	strcopy(request_header -> authorize , req_h[4]);
	strcopy(request_header -> cookie , req_h[5]);
	strcopy(request_header -> expect , req_h[6]);
	strcopy(request_header -> from , req_h[7]);
	strcopy(request_header -> host , req_h[8]);
	strcopy(request_header -> if_match , req_h[9]);
	strcopy(request_header -> if_mod_snc , req_h[10]);
	strcopy(request_header -> if_none_mtch , req_h[11]);
	strcopy(request_header -> if_range , req_h[12]);
	strcopy(request_header -> if_unmod_snc , req_h[13]);
	strcopy(request_header -> max_fwd , req_h[14]);
	strcopy(request_header -> proxy_auth , req_h[15]);
	strcopy(request_header -> range , req_h[16]);
	strcopy(request_header -> referer , req_h[17]);
	strcopy(request_header -> te , req_h[18]);
	strcopy(request_header -> uagent , req_h[19]);
	

	strcopy(entity_header_fld -> allow , entity_h[0]);
	strcopy(entity_header_fld -> content_encode , entity_h[1]);	
	strcopy(entity_header_fld -> content_lang , entity_h[2]);	
	strcopy(entity_header_fld -> content_len , entity_h[3]);
	strcopy(entity_header_fld -> content_loc , entity_h[4]);
	strcopy(entity_header_fld -> content_md5 , entity_h[5]);
	strcopy(entity_header_fld -> content_range , entity_h[6]);
	strcopy(entity_header_fld -> content_type , entity_h[7]);
	strcopy(entity_header_fld -> expires , entity_h[8]);
	strcopy(entity_header_fld -> last_mod , entity_h[9]);
	strcopy(msg_body -> msg , "");
	

	http_request -> req_fld = request_line;
	http_request -> general_fld = gen_header;
	http_request ->	request_fld = request_header;
	http_request -> entity_fld = entity_header_fld;
	http_request -> msg_body = msg_body;
	http_request -> msg_trailer = strdup("\0");
return http_request;
}
void free_it(void **ptr)
{
	if (NULL != *ptr)
	{
		free(*ptr);
		*ptr = NULL;
	}
}
void free_http_packets(struct HTTP_REQUEST **http_request,struct HTTP_RESPONSE **http_response)
{
	if (http_response != NULL && *http_response != NULL)
	{
	
		free_it((void*)&((*http_response) -> status_line));

		free_it((void*)&((*http_response) ->general_header));
	
		free_it((void*)&((*http_response) ->response_line));
	
	
		free_it((void*)&((*http_response) ->entity_header_fld));

		free_it((void*)&((*http_response)->msg_body));

		free_it((void*)&((*http_response)->msg_trailer));
	
		free_it((void*)(http_response));
	}
	if(http_request != NULL && *http_request != NULL)
	{
		
		free_it((void*)&((*http_request) -> req_fld));
	
		free_it((void*)&((*http_request) -> general_fld));
	
	
		free_it((void*)&((*http_request) -> request_fld));

		free_it((void*)&((*http_request) -> entity_fld));
		
		free_it((void*)&((*http_request) -> msg_body));
	
		free_it((void*)&((*http_request) -> msg_trailer));
	
		free_it((void*)(http_request));
	}
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
void print_data(FILE *fp,char *field,char * value)
{
	if (value != NULL)
	{
		fprintf(fp,"\n%s%s\n",field,value);
	}
}
void print_http_response(struct HTTP_RESPONSE *http_response,FILE *fp)
{
	fprintf(fp,"\nHTTP response packet\n");
	fprintf(fp,"\n---------------------------------------------------\n");
	print_data(fp,"protocol:",http_response -> status_line -> protocol);
	print_data(fp,"version:",http_response -> status_line -> version);
	print_data(fp,"status-line:",http_response -> status_line ->status);
	
	print_data(fp,"cache control:",http_response -> general_header -> cache_control );
	print_data(fp,"connection:",http_response ->general_header -> connection);
	print_data(fp,"date:",http_response ->general_header-> date);
	print_data(fp,"pragma:",http_response ->general_header -> pragma);
	print_data(fp,"trailer:",http_response ->general_header -> trailer);
	print_data(fp,"transfer coding:",http_response ->general_header -> transfercoding);
	print_data(fp,"upgrade:",http_response ->general_header -> upgrade);
	print_data(fp,"via:",http_response ->general_header -> via);
	print_data(fp,"warning:",http_response ->general_header -> warning);
	
	print_data(fp,"accept-ranges:",http_response ->response_line -> accept_ranges);
	print_data(fp,"age:",http_response ->response_line -> age);
	print_data(fp,"e-tag:",http_response ->response_line -> etag);
	print_data(fp,"location",http_response ->response_line -> location);
	print_data(fp,"proxy-authentication:",http_response ->response_line -> proxy_auth);
	print_data(fp,"retry-after:",http_response ->response_line -> retry_after);
	print_data(fp,"server:",http_response ->response_line -> server);
	print_data(fp,"set-cookie:",http_response ->response_line -> set_cookie);
	print_data(fp,"vary:",http_response ->response_line -> vary);
	print_data(fp,"www-auth:",http_response ->response_line -> www_auth);
	
	print_data(fp,"allow:",http_response ->entity_header_fld -> allow);
	print_data(fp,"content-encode:",http_response ->entity_header_fld -> content_encode);
	print_data(fp,"content-language:",http_response ->entity_header_fld -> content_lang);
	print_data(fp,"content-length:",http_response ->entity_header_fld -> content_len);
	print_data(fp,"content-location:",http_response ->entity_header_fld -> content_loc);
	print_data(fp,"content-MD5:",http_response ->entity_header_fld -> content_md5);
	print_data(fp,"content-rage:",http_response ->entity_header_fld -> content_range);
	print_data(fp,"content-type:",http_response ->entity_header_fld -> content_type);
	print_data(fp,"expires:",http_response ->entity_header_fld -> expires);
	print_data(fp,"last-modified:",http_response ->entity_header_fld -> last_mod);
	fprintf(fp,"\n---------------------------------------------------\n");
}
void print_http_request(struct HTTP_REQUEST *http_request,FILE *fp)
{
	fprintf(fp,"\nHTTP request packet\n");
	fprintf(fp,"\n---------------------------------------------------\n");
	print_data(fp,"method:",http_request -> req_fld -> method);
	print_data(fp,"url:",http_request -> req_fld -> url);
	print_data(fp,"protocol:",http_request -> req_fld ->protocol);
	print_data(fp,"protocol version:",http_request -> req_fld ->pversion);
	
	print_data(fp,"cache control:",http_request -> general_fld -> cache_control );
	print_data(fp,"connection:",http_request ->general_fld -> connection);
	print_data(fp,"date:",http_request ->general_fld  -> date);
	print_data(fp,"pragma:",http_request ->general_fld -> pragma);
	print_data(fp,"trailer:",http_request ->general_fld -> trailer);
	print_data(fp,"transfer coding:",http_request ->general_fld -> transfercoding);
	print_data(fp,"upgrade:",http_request ->general_fld -> upgrade);
	print_data(fp,"via:",http_request ->general_fld -> via);
	print_data(fp,"warning:",http_request ->general_fld -> warning);
	
	print_data(fp,"accept:",http_request ->request_fld -> accept);
	print_data(fp,"accept-char-set:",http_request ->request_fld -> acc_chr_set);
	print_data(fp,"accept-encode:",http_request ->request_fld -> acc_encode);
	print_data(fp,"accapt-language:",http_request ->request_fld -> acc_lang);
	print_data(fp,"authorize:",http_request ->request_fld -> authorize);
	print_data(fp,"cookie:",http_request ->request_fld -> cookie);
	print_data(fp,"expect:",http_request ->request_fld -> expect);
	print_data(fp,"from:",http_request ->request_fld -> from);
	print_data(fp,"host:",http_request ->request_fld -> host);
	print_data(fp,"if-match:",http_request ->request_fld -> if_match);
	print_data(fp,"if-modified-since:",http_request ->request_fld -> if_mod_snc);
	print_data(fp,"if-none-match:",http_request ->request_fld -> if_none_mtch);
	print_data(fp,"if-range:",http_request ->request_fld -> if_range);
	print_data(fp,"if-unmodified-since:",http_request ->request_fld -> if_unmod_snc);
	print_data(fp,"max-forward:",http_request ->request_fld -> max_fwd);
	print_data(fp,"proxy-authentication:",http_request ->request_fld -> proxy_auth);
	print_data(fp,"range:",http_request ->request_fld -> range);
	print_data(fp,"referer:",http_request ->request_fld -> referer);
	print_data(fp,"TE:",http_request ->request_fld -> te);
	print_data(fp,"user-agent:",http_request ->request_fld -> uagent);
	
	print_data(fp,"allow:",http_request ->entity_fld -> allow);
	print_data(fp,"content-encode:",http_request ->entity_fld -> content_encode);
	print_data(fp,"content-language:",http_request ->entity_fld -> content_lang);
	print_data(fp,"content-length:",http_request ->entity_fld -> content_len);
	print_data(fp,"content-location:",http_request ->entity_fld -> content_loc);
	print_data(fp,"content-MD5:",http_request ->entity_fld -> content_md5);
	print_data(fp,"content-rage:",http_request ->entity_fld -> content_range);
	print_data(fp,"content-type:",http_request ->entity_fld -> content_type);
	print_data(fp,"expires:",http_request ->entity_fld -> expires);
	print_data(fp,"last-modified:",http_request ->entity_fld -> last_mod);
	fprintf(fp,"\n---------------------------------------------------\n");
}
int read_chunked_msg(int socket,char msg[MAX_RCV_MSG_SIZE],int *processing)
{
int read_bytes = 0;
int length = 0;
char line[MAX_FIELD_LEN];
int cur_chunk = 0;
	memset(msg,'\0',MAX_RCV_MSG_SIZE);
	while (read_bytes < MAX_RCV_MSG_SIZE)
	{
			parse_line(socket,processing,line);
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
			parse_line(socket,processing,line);
	}
return SUCCESS;
}
struct HTTP_REQUEST * parse_http_request(int socket,int *index,int *keep_alive)
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
	parse_line(socket,keep_alive,request);
	
	printf("\nrequest line %s\n",request);
	if (strlen(request) > 5)
	{
		ptr = strstr(request," HTTP/");
	}
        if (ptr == NULL)
        {
               	printf("NOT HTTP !\n");
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
			if (ptr != NULL)
			{
				*ptr = '\0';
			}
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
			read_chunked_msg(socket,requested,keep_alive);
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
int last_modified(char *requested,char *time)
{
	struct tm *date;
	struct stat attrib;
	stat(requested, &attrib);
	date = gmtime(&(attrib.st_mtime));
	sprintf(time,"%d/%d/%d %d:%d", (date->tm_year)+1900,(date->tm_mon)+1, date->tm_mday,date->tm_hour,date->tm_min);
	return SUCCESS;
}
int retrieve_page_info(struct HTTP_REQUEST *request,struct HTTP_RESPONSE *response)
{
	char *requested = request -> req_fld -> url;
        struct stat buf;
        int file_size = 0;
        char buffer[MAX_BUFF];
	char date[MAX_BUFF];
	char *ptr = NULL;
	int i = 0;
        FILE *fp = fopen(requested,"r");
        if (NULL == fp)
        {
                return FAILURE;
        }
        else
        {
                stat(requested,&buf);
                file_size = buf.st_size;
                memset(buffer,'\0',MAX_BUFF);
		memset(date,'\0',MAX_BUFF);
                if (FAILURE == last_modified(requested,date))
                {
                        return FAILURE;
                }
                else
                {
			
	               if(NULL != requested)
        	        {
                	        ptr = strchr(requested,'.');
				if (ptr != NULL )
				{
		                        for (i = 0; extensions[i].ext != NULL; i++)
		                        {
	        	                        if (strcmp(ptr + 1, extensions[i].ext) == 0)
	                	                {
                       					strcpy(response -> entity_header_fld -> content_type ,"Content-Type: ");
	                       				strcat(response -> entity_header_fld -> content_type ,extensions[i].mediatype);
							break;
						}
					}
				}
			}
                       	//strcpy(response -> entity_header_fld -> content_type ,"Content-Type:text/html");
                        sprintf(buffer,"Content-Length: %d",file_size);
                        strcpy(response -> entity_header_fld -> content_len ,buffer);
			
                        sprintf(buffer,"Last-Modified: %s",date);
			strcpy(response -> entity_header_fld ->last_mod ,buffer);
                }
        }
fclose(fp);
return SUCCESS;
}
void add_field(char **destination,char *source)
{
	if (*destination == NULL)
	{
		*destination = (char*)malloc(sizeof(char)*(strlen(source) + 1));
	}
	if (strlen(source) > 0)
	{
		*destination = realloc(*destination,strlen(*destination)+strlen(source) + 4);
		strcat(*destination,source);
		strcat(*destination,"\r\n");
	}
}
void create_http_response_msg(http_response_packet *http_res,struct HTTP_RESPONSE *response)
{
	char buffer[MAX_FIELD_LEN];
	sprintf(buffer,"%s/%s %s",response -> status_line -> protocol,response -> status_line -> version,response -> status_line -> status);
	add_field(&(http_res->status_line),buffer);

	add_field(&(http_res->general_header),response->general_header->cache_control);
	add_field(&(http_res->general_header),response->general_header->connection);
	add_field(&(http_res->general_header),response ->general_header-> date);
	add_field(&(http_res->general_header),response ->general_header -> pragma);
	add_field(&(http_res->general_header),response ->general_header -> trailer);
	add_field(&(http_res->general_header),response ->general_header -> transfercoding);
	add_field(&(http_res->general_header),response ->general_header -> upgrade);
	add_field(&(http_res->general_header),response ->general_header -> via);
	add_field(&(http_res->general_header),response ->general_header -> warning);
	

	add_field(&(http_res->entity_header),response->entity_header_fld->content_type);
	add_field(&(http_res->entity_header),response->entity_header_fld->content_len);
	add_field(&(http_res->entity_header),response->entity_header_fld->last_mod);

	add_field(&(http_res->response_header),response->response_line->accept_ranges);
	add_field(&(http_res->response_header),response ->response_line -> age);
	add_field(&(http_res->response_header),response ->response_line -> etag);
	add_field(&(http_res->response_header),response ->response_line -> location);
	add_field(&(http_res->response_header),response ->response_line -> proxy_auth);
	add_field(&(http_res->response_header),response ->response_line -> retry_after);
	add_field(&(http_res->response_header),response ->response_line -> server);
	add_field(&(http_res->response_header),response ->response_line -> set_cookie);
	add_field(&(http_res->response_header),response ->response_line -> vary);
	add_field(&(http_res->response_header),response ->response_line -> www_auth);
	
	add_field(&(http_res->entity_header),response ->entity_header_fld -> allow);
	add_field(&(http_res->entity_header),response ->entity_header_fld -> content_encode);
	add_field(&(http_res->entity_header),response ->entity_header_fld -> content_lang);
	add_field(&(http_res->entity_header),response ->entity_header_fld -> content_len);
	add_field(&(http_res->entity_header),response ->entity_header_fld -> content_loc);
	add_field(&(http_res->entity_header),response ->entity_header_fld -> content_md5);
	add_field(&(http_res->entity_header),response ->entity_header_fld -> content_range);
	add_field(&(http_res->entity_header),response ->entity_header_fld -> content_type);
	add_field(&(http_res->entity_header),response ->entity_header_fld -> expires);
	add_field(&(http_res->entity_header),response ->entity_header_fld -> last_mod);

        http_res -> msg_body = strdup(response->msg_body->msg);
       	http_res -> msg_trailer = strdup("\0");
}
int create_http_head_response_pack(struct HTTP_REQUEST *request,struct HTTP_RESPONSE *response,http_response_packet *http_res)
{
        http_res -> status_line = NULL;
        http_res -> general_header = NULL;
        http_res -> response_header = NULL;
        http_res -> entity_header = NULL;
        http_res -> msg_body = NULL;
        http_res -> msg_trailer = NULL;
	int success_failure = 0;

	if (FAILURE == retrieve_page_info(request,response))
	{
		strcpy(response -> status_line -> protocol,"HTTP");
		strcpy(response -> status_line -> version ,"1.1");
		strcpy(response -> status_line -> status ,NOTFOUND);
		strcpy(response -> response_line -> server ,SERVER);	
		strcpy(response -> response_line -> accept_ranges ,"Accept-Ranges: Bytes");
		if (KEEP_ALIVE && strstr(request->general_fld->connection,"Keep-Alive") != NULL)
		{
			strcpy(response->general_header->connection,"Connection: Keep-Alive");
		}
		else
		{
			strcpy(response->general_header->connection,"Connection: Close");
		}
		success_failure = 1;
	}
	else
	{
		strcpy(response -> status_line -> protocol,"HTTP");
		strcpy(response -> status_line -> version ,"1.1");
		strcpy(response -> status_line -> status ,OK);
		strcpy(response -> response_line -> server ,SERVER);	
		strcpy(response -> response_line -> accept_ranges ,"Accept-Ranges: Bytes");
		if (KEEP_ALIVE && (strstr(request->general_fld->connection,"Keep-Alive") != NULL))
		{
			strcpy(response->general_header->connection,"Connection: Keep-Alive");
		}
		else
		{
			strcpy(response->general_header->connection,"Connection: Close");
		}
		strcpy(response->msg_body->msg,request->req_fld->url);
	}
	if (CACHE)
	{
		strcpy(response->general_header->cache_control,"Cache-Control: ");
		strcat(response->general_header->cache_control,MAX_CACHE_AGE);
	}
	else
	{
		strcpy(response->general_header->cache_control,"Cache-Control: No-Cache");
	}
	create_http_response_msg(http_res,response);

return success_failure;
}
int create_http_response_pack(http_response_packet *http_res,struct HTTP_REQUEST *request,struct HTTP_RESPONSE **response)
{
struct HTTP_RESPONSE *http_response;
int method = find_method(request -> req_fld -> method);

	http_response = HTTP_response_packet();
	if(method > MAX_METHODS)
	{
		printf("\nUnknown method\n");	
		return FAILURE;
	}
	else
	{
		if (FAILURE == create_http_head_response_pack(request,http_response,http_res))
		{
			*response = http_response;
			return FAILURE;
		}
	}
	*response = http_response;
return SUCCESS;
}
/*int start_server()
{

}
int authenticate_user()
{

}*/
int update_log(char *log_file,const char *log)
{	
FILE *log_f = fopen(log_file,"a+");
	if (0 == fprintf(log_f,"%s",log))
	{
		return FAILURE;
	}
	fflush(log_f);
fclose(log_f);
return SUCCESS;
}

int read_line(int fd,char *message)
{
        int reads = 0;
        reads = read(fd,message,1024);
        if (FILE_ERROR == reads)
        {
                perror("\nError in reading a string from file descriptor ");
                return FAILURE;
        }
        message[reads] = '\0';
return SUCCESS;
}
int is_phppage(char *requested)
{
char *ptr = NULL;
	if (NULL == requested)
	{
		printf("\nunknown request\n");
		return FAILURE;
	}
	ptr = strchr(requested, '.');
	if (ptr != NULL && strncmp(ptr + 1, "php",3) == 0)
	{
		return SUCCESS;
	}
return FAILURE;
}
int is_htmlpage(char *requested)
{
char *ptr = NULL;
	if (NULL == requested)
	{
		printf("\nunknown request\n");
		return FAILURE;
	}
	ptr = strchr(requested, '.');
	if (ptr!= NULL && strncmp(ptr+ 1, "html",4) == 0)
	{
		return SUCCESS;
	}
return FAILURE;
}
int get_file_size(int fd) 
{
	struct stat stat_struct;
	if (fstat(fd, &stat_struct) == -1)
	{
		return (1);
	}
	return (int) stat_struct.st_size;
}
void replace(char *s, char old, char new)
{
	char *p = s;

	while(*p != '\0')
	{
		if(*p == old)
		*p = new;
		++p;
	}
}
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
int peer_addr(int s, char *buf, int bufsiz) 
{
	int z;
	struct sockaddr_in adr_inet;/* AF_INET */
	int len_inet; /* length */


	/*
	* Obtain the address of the socket:
	*/
	len_inet = sizeof adr_inet;


	z = getpeername(s, (struct sockaddr *)&adr_inet, &len_inet);
	if ( z == -1) 
	{
		return FAILURE; /* Failed */
	}


	/*
	* Convert address into a string
	* form that can be displayed:
	*/
	sprintf(buf,"%s:%u",inet_ntoa(adr_inet.sin_addr),(unsigned)ntohs(adr_inet.sin_port));


return SUCCESS;
}
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
int encode_msg(char *msg)
{
	int length = 0;
	int i = 0;
	int j = 0;
	char temp[MAX_RCV_MSG_SIZE];
	memset(temp,'\0',MAX_RCV_MSG_SIZE);
	length = strlen(msg);
	for (i = 0; i < length; i++)
	{
		if (msg[i]=='&' || msg[i] == ' ' || msg[i] == '\'' || msg[i]=='\"' || msg[i] == '\?')
		{
			temp[j]='\\';
			temp[j+1]=msg[i];
			j = j + 2;
		}
		else
		{
			temp[j] = msg[i];
			j++;
		}
			
	}
	strcpy(msg,temp);
return SUCCESS;
}
struct tm*get_current_time()
{
	time_t rawtime;
	struct tm * timeinfo;
	time (&rawtime);
	timeinfo = localtime (&rawtime);

return timeinfo;
}



