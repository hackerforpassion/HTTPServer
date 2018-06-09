/********************************************************************************
                                FILE HEADER
* NAME :

* DESCRIPTION :

* DATE          AUTHOR          REFERENCE               PURPOSE

********************************************************************************/

#include<serv.h>
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/


void call_php(struct HTTP_REQUEST *request,char *php_path,int socket)
{
char *url = strdup(request -> req_fld -> url);
int method = find_method(request -> req_fld -> method);
char *uri = NULL;
char buffer[MAX_RCV_MSG_SIZE];
char *script_filename = NULL;
char *query_string = NULL;
int tmp = -1;
//char sfile[20];
	memset(buffer,'\0',4096);
	//memset(sfile,'\0',20);
	if ((method == GET) || (method == POST))
	{
	        if (method == 4)
        	{
			//query_string = strdup(request -> msg_body ->msg);
			//script_filename = strdup(request -> req_fld -> url);
			if (NULL != request -> request_fld -> cookie);
			{
				setenv("HTTP_COOKIE",request -> request_fld -> cookie,1);
			}
			if (strlen(request->msg_body->msg) == 0)
			{
				perror("\nNo msg to write\n");
				write(socket,"error",10);
			}
			sprintf(buffer,"echo \"%s\" | REDIRECT_STATUS=CGI REQUEST_METHOD=POST SCRIPT_FILENAME=%s SCRIPT_NAME=%s  CONTENT_TYPE=application/x-www-form-urlencoded CONTENT_LENGTH=%d %s",request->msg_body->msg,request->req_fld->url,request->req_fld->url,strlen(request->msg_body->msg),php_path);
			//free(query_string);
			//free(script_filename);
			//free_http_packets(&request,NULL);
			//printf("\n%s\n",buffer);
			free(url);
			
			//sprintf(sfile,"%d",socket);
			tmp=dup(1);	
			//close(1);
			//fd1=dup(socket);	
			//close(socket);
			dup2(socket,STDOUT_FILENO);
			close(socket);
			//execl("./phppost","phppost",buffer,sfile,NULL);
			system(buffer);
			dup2(tmp,STDOUT_FILENO);
			//close(STDOUT_FILENO);
			//close(file);
			//exit(SUCCESS);
        	}
	        else if (method == GET)
	        {
			uri = strchr(url,'?');
			if (uri != NULL)
			{
				query_string = uri + 1;
				(*(uri)) = '\0';
				script_filename = url;
			}
			else
			{
				query_string = "";
				script_filename = url;
			}
			
        	        
			setenv("REQUEST_METHOD","GET",1);
	                setenv("REDIRECT_STATUS","CGI",1);
			if (NULL != request -> request_fld -> cookie);
			{
				setenv("HTTP_COOKIE",request -> request_fld -> cookie,1);
			}
	                setenv("GATEWAY_INTERFACE","CGI/1.1",1);
	                setenv("QUERY_STRING",query_string,1);
	                setenv("SCRIPT_FILENAME",script_filename,1);
			if(url != NULL)
			free(url);
			//free_http_packets(&request,NULL);
			//dup2(socket, STDOUT_FILENO);
			//execl(php_path,"php-cgi",NULL);
			tmp=dup(1);
                        //close(1);
                        //fd1=dup(socket);
                        //close(socket);
			dup2(socket,STDOUT_FILENO);
			close(socket);
			system(php_path);
			dup2(tmp,STDOUT_FILENO);
			//close(socket);
			//exit(SUCCESS);
		}
	}
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/

int serve(int socket,http_response_packet *http_res,char *log)
{
	int index = 0;
	char buffer[MAX_RCV_MSG_SIZE];
	struct stat buf;
	char * ptr = NULL;
	char php_path[MAX_BUFF];
	char *web_root = NULL;
	char content_len[20];
	struct HTTP_REQUEST *requested = NULL;
	struct HTTP_RESPONSE *response = NULL;
	int method = -1;
	int count = 0;
	FILE * log_file = NULL;
	int keep_alive = 1;
	int processing = 0;
	thread_count++;	
	char file_name[MAX_FIELD_LEN];
	char temp[MAX_FIELD_LEN];
	int file = -1;
	int attempts = 0;
	memset(file_name,'\0',MAX_FIELD_LEN);
	void alarm_handler(int signum)
        {
		attempts++;
		if (socket != -1)
		{
			close(socket);
			socket = -1;
		}
		thread_count--;
		printf("\nNumber of processes going on : %d\n",thread_count);
		pthread_detach(pthread_self());
		pthread_exit(NULL);
        }
	signal(SIGALRM, alarm_handler);
	printf("\nNumber of processes going on : %d\n",thread_count);
	if (FAILURE == peer_addr(socket,file_name,MAX_FIELD_LEN))
	{
		sprintf(file_name,"unknownclient");
	}
	printf("\nconnection from %s\n",file_name);
	//strcat(file_name,log);
	replace(file_name,'.','_');
	replace(file_name,'/','_');
	replace(file_name,' ','_');
	replace(file_name,'\n','_');
	replace(file_name,':','_');
	strcat(file_name,".txt");
	//printf("\ntmp file name %s\n",file_name);
	web_root = webroot();
	strcpy(temp,web_root);
	free(web_root);
	strcat(temp,"/temp/");
	strcat(temp,file_name);
	while((keep_alive == 1) && (count < MAX_ATTEMPTS) && (exit_server != 1))
	{
		count++;
		alarm(TIMER);
		LOGGER(LOG_CRITICAL,"Creating a persistent connection");
		requested = parse_http_request(socket,&index,&keep_alive);	
		if (requested == NULL)
		{
			continue;
		}
		//alarm(TIMER);
		printf("\ncreated request packet\n");
		method = find_method(requested->req_fld->method);
		if(method == GET && strstr(requested->req_fld->url,".html")==NULL && strstr(requested->req_fld->url,".php")==NULL && requested->req_fld->url[strlen(requested->req_fld->url)-1]!='/' && strstr(requested->req_fld->url,".txt") == NULL)	
		{
			 LOGGER(LOG_CRITICAL,"Sending media file");
			send_media_file(socket,requested->req_fld->url,DOWNLOAD);
			close(socket);
			socket = -1;
			keep_alive = 0;
			printf("\nFile  %s sent to client\n",requested->req_fld->url);
			update_log(log,"\nsent file to client\n");
		}
		else
		{
			if(requested == NULL)
			{
				 LOGGER(LOG_CRITICAL,"Unknown packet");
				continue;
			}
			if (strstr(requested->general_fld->connection,"Keep-Alive") == NULL)
			{
				LOGGER(LOG_CRITICAL,"connection is not keep alive");
				printf("\nconnection is not keep-alive\n");
				keep_alive = 0;
			}
			log_file = fopen(log,"w+");
			print_http_request(requested,log_file);
			//print_http_request(requested,stdout);
			fclose(log_file);
			memset(php_path,'\0',MAX_FIELD_LEN);
			memset(content_len,'\0',20);
			memset(buffer,'\0',MAX_RCV_MSG_SIZE);
			
			if (strstr(requested->msg_body->msg,"_method=put") != NULL)
			{
				method = PUT;
			}
			if ((method == PUT || method == POST))
			{
				strcat(requested->msg_body->msg," ");
				//encode_msg(requested->msg_body->msg);
			}
			if (PUT == method)
			{
				printf("\nPUT method\n");
				LOGGER(LOG_CRITICAL,"Method is put");
				//printf("\nmsg body %s \n",requested->msg_body->msg);
				if (strlen(requested->msg_body->msg) == 0)
				{
					LOGGER(LOG_CRITICAL,"MSG length is unknown");
					perror("\nNo msg to write\n");
					file = open(temp,O_WRONLY|O_CREAT,S_IRWXU);
					write(file,"error no msg to write",10);
					send_media_file(socket,temp,DISPLAY);
					close(file);
				}
				else if ((exit_server != 1)&&(fork()==0))
				{
					LOGGER(LOG_CRITICAL,"PUT method");
					file = open(temp,O_WRONLY|O_CREAT,S_IRWXU);
					sprintf(buffer,"./putpost 3 \'%s\' \'%s\' \'%d\'",requested->req_fld->url,requested->msg_body->msg,file);
					system(buffer);
					close(file);
					exit(SUCCESS);
				}
				else
				{	
					wait(NULL);
					strcpy(requested->req_fld->url,temp);	
					printf("sending %s to client",requested->req_fld->url);
					LOGGER(LOG_CRITICAL,"Sending Data to client");
					send_media_file(socket,requested->req_fld->url,DISPLAY);
					sprintf(buffer,"rm %s",requested->req_fld->url);
					system(buffer);
					close(socket);
					socket = -1;
					keep_alive = 0;
				}
			}
			else
			{
				//printf("\nmsg body %s \n",requested->msg_body->msg);
				if (POST == method && requested->req_fld->url[strlen(requested->req_fld->url)-1]=='/')
				{
					if (strlen(requested->msg_body->msg) == 0)
					{
						perror("\nNo msg to write\n");
						file = open(temp,O_WRONLY|O_CREAT,S_IRWXU);
						write(file,"error no msg to write",10);
					 	LOGGER(LOG_CRITICAL,"No message to write");
						send_media_file(socket,temp,DISPLAY);
						close(file);
					}
					else if ((exit_server != 1)&&(fork()==0))
					{
						file = open(temp,O_WRONLY|O_CREAT,S_IRWXU);
						sprintf(buffer,"./putpost 4 '%s' '%s' '%d'",requested->req_fld->url,requested->msg_body->msg,file);
						system(buffer);
						LOGGER(LOG_CRITICAL,"Method is post");
						close(file);
						exit(SUCCESS);
					}
					else
					{	
						wait(NULL);
						strcpy(requested->req_fld->url,temp);	
						printf("sending %s to client",requested->req_fld->url);
						LOGGER(LOG_CRITICAL,"Sending data to client");
						send_media_file(socket,requested->req_fld->url,DISPLAY);
						sprintf(buffer,"rm %s",requested->req_fld->url);
						system(buffer);
						close(socket);
						socket = -1;
						keep_alive = 0;
					}
				}
				else 
				{
					if (method == GET && requested->req_fld->url[strlen(requested -> req_fld -> url) - 1] == '/')
					{
						web_root=webroot();
						setenv("WEBDIR",requested->req_fld->url,1);
						sprintf(buffer,"%s/WEB/index.php",web_root);
						free(web_root);
						strcpy(requested->req_fld->url,buffer);
								
					}
					if (SUCCESS == is_phppage(requested -> req_fld -> url) && (method == GET || method == POST))
					{
						printf("\nits a php page\n");	
						strcpy(buffer,requested -> req_fld -> url);
						ptr = (strchr(buffer,'?'));
						if (ptr != NULL)
						{
							*ptr = '\0';
						}
						if (-1 != stat(buffer,&buf))
						{
							update_log(log,"\nHTTP/1.1 200 OK\n php page is served by php cgi\n");
						}
						else
						{
							update_log(log,"\nHTTP/1.1 204 NOCONTENT\n");
						}
						if((exit_server != 1)&&(fork()==0))
						{
							printf("php request");
							fflush(stdout);
							web_root = webroot();
							sprintf(php_path,"%s/php-5.6.3/sapi/cgi/php-cgi",web_root);
							free(web_root);
							file = open(temp,O_WRONLY|O_CREAT,S_IRWXU);
							call_php(requested,php_path,file);
							exit(SUCCESS);
						}
						else
						{	
							wait(NULL);
							strcpy(requested->req_fld->url,temp);	
							LOGGER(LOG_CRITICAL,"PHP result is sent to client");
							printf("sending %s to client",requested->req_fld->url);
							send_media_file(socket,requested->req_fld->url,DISPLAY);
							sprintf(buffer,"rm %s",requested->req_fld->url);
							system(buffer);
							close(socket);
							socket = -1;
							keep_alive = 0;
						}
					}
					else
					{
						if ((requested->req_fld->url[strlen(requested -> req_fld -> url) - 1] == '/') && method != POST)
						{
							sprintf(buffer,"%sindex.html",requested->req_fld->url);
							strcpy(requested -> req_fld -> url ,buffer);
						}
						printf("\nurl requested is %s\n",requested->req_fld->url);	
						printf("\nits a  GET or HEAD or POST request request\n");
						
						if (exit_server != 1)
						{
							if ( FAILURE == create_http_response_pack(http_res,requested,&response))
							{
								update_log(log,"\nunable to create response packet page not found\n");	
								send_http_response_pack(socket,http_res,method);
								printf("404 File not found Error\n");
								LOGGER(LOG_CRITICAL,"Page not found");
								send_new(socket,"404 NOTFOUND\r\n");
							}
							else
							{
								if (method == GET || method == HEAD || method == POST)
								{
									send_http_response_pack(socket,http_res,method);
								}
								if(method == GET)
								{	
									send_file(socket,requested->req_fld->url);
									printf("\nFile  sent to client\n");
									LOGGER(LOG_CRITICAL,"File sent to client");		
									update_log(log,"\nsent page to client\n");		
								}
							}
							log_file = fopen(log,"w+");
							print_http_response(response,log_file);
							fclose(log_file);
							if (http_res != NULL)
							{
								free_it((void*)&(http_res->status_line));
								free_it((void*)&(http_res->general_header));
								free_it((void*)&(http_res->response_header));
								free_it((void*)&(http_res->entity_header));
								free_it((void*)&(http_res->msg_body));
								free_it((void*)&(http_res->msg_trailer));
							}
						}
					}
				}
			}
		}
		printf("\nfreeing http  packets\n");
		if (requested != NULL)
		{
			free_http_packets(&requested,&response);
		}
		printf("\nhttp packets are freed\n");
		LOGGER(LOG_CRITICAL,"Freeing HTTP packets");
		processing = 0;
	}
	if (socket != -1)
	{
		close(socket);
		socket = -1;
	}
	thread_count--;
	printf("\nNumber of processes going on : %d\n",thread_count);
	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/


void *serve_client(void* new_socket)
{
	int socket = *((int*)new_socket);
	char details[MAX_FIELD_LEN];
	http_response_packet http_res;	char log_f[MAX_FIELD_LEN];
	char log_num[20];
	char buffer[MAX_FIELD_LEN];
	int log = 0;
	char *web_root = NULL;
	free((int*)new_socket);
	
	LOGGER(LOG_CRITICAL,"Starting new thread");
	memset(details,'\0',100);
	if (FAILURE == peer_addr(socket,details,MAX_FIELD_LEN))
	{
		LOGGER(LOG_CRITICAL,"Unknown client");
		sprintf(details,"unknown client");
	}
	//printf("Connection accepted from %s",details);
        if (-1 == socket)
        {
		update_log("log.txt","\nError receiving from client\n");
        }
        else
        {
               //printf("\nREQUEST RECEIVED!!!\n\n%s\n",read_buf);
		pthread_mutex_lock(&log_mutex);
		log = log_count;
		log_count++;
		pthread_mutex_unlock(&log_mutex);
		memset(log_f,'\0',MAX_FIELD_LEN);
		memset(log_num,'\0',20);
		memset(buffer,'\0',MAX_FIELD_LEN);
		sprintf(log_f,"%s",asctime(get_current_time()));
		web_root = webroot();
		sprintf(buffer,"\nrequest from  client %s at %s,log details are stored in %s/log/",details,log_f,web_root);
		replace(log_f,' ','_');
		replace(log_f,'\n','_');
		replace(log_f,':','_');
		strcat(buffer,log_f);
		sprintf(log_num,"?%d",log);
		strcat(buffer,log_num);
		strcat(buffer,".log\n");
		update_log("log.txt",buffer);
		sprintf(buffer,"%s/log/%s%s.log",web_root,log_f,log_num);
		free(web_root);
		//printf("\ncalling serve function\n");
		if (exit_server != 1)
		{
			 LOGGER(LOG_CRITICAL,"invoking serve client finction");
			serve(socket,&http_res,buffer);
		}
		//printf("\nfinished serve function\n");
		printf("\nServed client %s\n",details);
	//	thread_count--;
        }

//close(socket);
pthread_detach(pthread_self());
pthread_exit(NULL);
}
/******************************************************************************
                                FUNCTION HEADER
* NAME :

* DESCRIPTION :

* RETURN :

******************************************************************************/

int main(int argc , char *argv[])
{
	LOGGER(LOG_CRITICAL,"Server is starting");
        int c;
        struct sockaddr_in server , client;
        int *new_socket = NULL;
        char buf[MAX_BUFF];
        int new_s = -1;
        int *shared_flag = NULL;
        int *status = NULL;
        pthread_t tid = -1;
	LOGGER(LOG_CRITICAL,"Creating IPC for communication with admin");
        if (init_shared_flag(&shared_flag,'u') == FAILURE)
        {
                printf("\nPlease run admin first\n");
                exit(SUCCESS);
        }
        if (init_shared_flag(&status,'i') == FAILURE)
        {
                printf("\nPlease run admin first\n");
                exit(SUCCESS);
        }
        *shared_flag = STOP_SERVER;
        *status = 1;
        //Create socket
        socket_desc = socket(AF_INET , SOCK_STREAM , 0);
        if (socket_desc == -1)
        {	
		A_ERROR(ERROR_CRITICAL,ERROR_SOCKET_CREATION);
                printf("Could not create socket");
                exit(FAILURE);
        }
        //Prepare the sockaddr_in structure
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(atoi(argv[1]));
        //Bind
        if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
        {
                puts("bind failed");
		A_ERROR(ERROR_CRITICAL,ERROR_SOCKET_CREATION);
                return 1;
        }
        puts("bind done");
        //Listen
        listen(socket_desc , 10); //Accept and incoming connection
         // Put the socket in non-blocking mode:
        if(fcntl(socket_desc, F_SETFL, fcntl(socket_desc, F_GETFL) | O_NONBLOCK) < 0)
        {
		A_ERROR(ERROR_CRITICAL,ERROR_SOCKET_CREATION);
                perror("\nerror setting socket in non blocking mode\n");
        }
        else
        {
                printf("\nYour socket is non blocking\n");
       	}

        puts("Waiting for incoming client connections...");
        c = sizeof(struct sockaddr_in);
        void alarm_handler()
        {
                close(socket_desc);
                printf("\nServer is exiting....\n");
                printf("\nNumber of processes going on:%d\n",thread_count);
		exit(SUCCESS);
	}
	void signal_handler(int signum)
        {
                *status = -1;
                exit_server = 1;
                printf("\nServer is going to exit....\n");
                printf("\nNumber of processes going on:%d\n",thread_count);
                alarm(15);
                signal(SIGALRM, alarm_handler);
        }
        /*void seg_handle(int signum)
        {
                perror("\nsegmentation violation occured\n");
        }*/
        signal(SIGINT,signal_handler);
        signal(SIGPIPE,SIG_IGN);
        printf("\nMonitoring.....\n");
        printf("\nControl the server from admin\n");
        while(*shared_flag != EXIT_MONITOR)
        {
                if (*shared_flag == STOP_SERVER)
                {
                        exit_server = 1;
                }
                if (*shared_flag == RUN_SERVER)
                {
                        exit_server = 0;
                        if ((new_s = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)))
                        {
                                if (new_s != EAGAIN && new_s != ERROR)
                                {
                                        new_socket = (int*)malloc(sizeof(int));
                                        *new_socket = new_s;
                                        printf("Connection from %s\n",inet_ntop(AF_INET,&client.sin_addr,buf,sizeof(buf)));
                                        fflush(stdout);
                                        if (thread_count <= MAX_PROCESSES)
                                        {
                                                if (exit_server != 1 && pthread_create(&tid,NULL,serve_client,(void*)(new_socket)) != 0)
                                                {
                                                        perror("\nError creating thread for serving a client\n");
                                                        continue;
                                                }
                                        }
                                        else
                                        {
                                                close((*new_socket));
                                                free(new_socket);
						A_ERROR(ERROR_CRITICAL,ERROR_SOCKET_CREATION);
                                                printf("\naccept failed\n");
                                                continue;
                                        }
                                        printf("\nNumber of processes running %d\n",thread_count);
                                }
                        }
                }
        }
	LOGGER(LOG_CRITICAL,"Server is starting");
        printf("\nMonitoring program is exiting..");
        printf("\nServer is going to exit....\n");
        printf("\nNumber of processes going on:%d\n",thread_count);
        *status = -1;
        exit_server = 1;
  *shared_flag = EXIT_MONITOR;
        detach_shared_flag(shared_flag);
        detach_shared_flag(status);
        sleep(TIMER);
        close(socket_desc);
exit(SUCCESS);
}

