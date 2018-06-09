#ifndef HTTP_STATUS_CODES

#define HTTP_STATUS_CODES
#include<stdio.h>
#include<logger.h>
#include<anagram.h>
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
extern int socket_desc ;
extern int exit_server;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
extern int thread_count ;
extern unsigned int log_count ;
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
        struct http_req         *req_fld;
        struct http_gen_header  *general_fld;
        struct http_client_req  *request_fld;
        struct entity_header    *entity_fld;
        struct msg              *msg_body;
        char                    *msg_trailer;
};
struct http_status
{
        char protocol[MAX_FIELD_LEN];
        char version[MAX_FIELD_LEN];
        char  status[MAX_FIELD_LEN];
};
struct HTTP_RESPONSE
{
        struct http_status      *status_line;
        struct http_gen_header  *general_header;
        struct http_srv_res *response_line;
        struct entity_header    *entity_header_fld;
        struct msg              *msg_body;
        char                    * msg_trailer;
};
typedef struct {
        char *ext;
        char *mediatype;
} extn;
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
int get_file_size(int fd);
void replace(char *s, char old, char new);
int send_file(int fd,char *requested);
int peer_addr(int s, char *buf, int bufsiz);
int send_media_file(int fd,char *resource,int media_type);
int encode_msg(char *msg);
int serve(int socket,http_response_packet *http_res,char *log);
struct tm*get_current_time();
int init_shared_flag(int **shared_memory,key_t shm_key);
void detach_shared_flag(int *shared_memory);

//Possible media types

#endif

