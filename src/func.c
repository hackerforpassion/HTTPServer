/********************************************************************************
                                FILE HEADER
* NAME :

* DESCRIPTION :

* DATE          AUTHOR          REFERENCE               PURPOSE

********************************************************************************/

/******************************************************************************
*				HEADER FILES
******************************************************************************/
#include<server.h>
/******************************************************************************
*			Global data Declarations
******************************************************************************/
char *method[MAX_METHODS]={     "GET",
                                "HEAD",
                                "PUT",
                                "POST"};
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/

int get_date(char *file,char *buffer)
{
        struct stat buf;
        struct tm *mtime;
        stat(file,&buf);
        mtime = gmtime(&(buf.st_mtime));
        sprintf(buffer,"Last modified %u/%u/%u; %u:%u",(mtime->tm_year) + 1900,(mtime->tm_mon) + 1,mtime->tm_mday,mtime->tm_hour,mtime->tm_min);
        return 0;
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/

void send_new(int fd, char *msg)
{
        int len = strlen(msg);
        if (send(fd, msg, len - 1, 0) == -1)
        {
                printf("Error in send\n");
        }
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
int init_shared_flag(int **shared_memory,key_t shm_key)
{
  int segment_id;
  const int shared_segment_size = 0x04;
  /* Allocate a shared memory segment. */
  if ((segment_id = shmget (shm_key, shared_segment_size,S_IRUSR | S_IWUSR)) == ERROR)
  {
        return FAILURE;
  }
  /* Attach the shared memory segment*/
  *shared_memory = (int*) shmat (segment_id, 0, 0);
  if (*shared_memory == NULL)
  {
        return FAILURE;
  }
  /* Detach the shared memory segment. */
   return SUCCESS;
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
void detach_shared_flag(int *shared_memory)
{
  shmdt (shared_memory);
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
void main_thread_alarm(int signum)
{	
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
struct tm*get_current_time()
{
        time_t rawtime;
        struct tm * timeinfo;
        time (&rawtime);
        timeinfo = localtime (&rawtime);

return timeinfo;
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
int get_file_size(int fd)
{
        struct stat stat_struct;
        if (fstat(fd, &stat_struct) == -1)
        {
                return (1);
        }
        return (int) stat_struct.st_size;
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
int last_modified(char *requested,char *time)
{
        struct tm *date;
        struct stat attrib;
        stat(requested, &attrib);
        date = gmtime(&(attrib.st_mtime));
        sprintf(time,"%d/%d/%d %d:%d", (date->tm_year)+1900,(date->tm_mon)+1, date->tm_mday,date->tm_hour,date->tm_min);
        return SUCCESS;
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
void print_data(FILE *fp,char *field,char * value)
{
        if (value != NULL)
        {
                fprintf(fp,"\n%s%s\n",field,value);
        }
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
void free_it(void **ptr)
{
        if (NULL != *ptr)
        {
                free(*ptr);
                *ptr = NULL;
        }
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
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
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/
struct HTTP_REQUEST * http_request_packet(char req_line[MAX_METHODS][MAX_FIELD_LEN],char gen_h[GEN_H_CNT][MAX_FIELD_LEN],char req_h[REQ_H_CNT][MAX_FIELD_LEN],char entity_h[ENTITY_H_CNT][MAX_FIELD_LEN])
{
        struct HTTP_REQUEST     *http_request;

        struct http_req         *request_line;
        struct http_gen_header  *gen_header;
        struct http_client_req  *request_header;
        struct entity_header    *entity_header_fld;
        struct msg              *msg_body;
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
        http_request -> request_fld = request_header;
        http_request -> entity_fld = entity_header_fld;
        http_request -> msg_body = msg_body;
        http_request -> msg_trailer = strdup("\0");
return http_request;
}
struct HTTP_RESPONSE * HTTP_response_packet()
{
        struct HTTP_RESPONSE *http_response;

        struct http_status              *status_line = NULL;
        struct http_gen_header          *gen_header = NULL;
        struct http_srv_res     *response_header = NULL;
        struct entity_header            *entity_header_fld = NULL;
        struct msg                      *msg_body = NULL;
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

