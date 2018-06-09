#include<sheader.h>
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
void *serve_client(void* new_socket)
{
        int socket = *((int*)new_socket);
        char details[MAX_FIELD_LEN];
        http_response_packet http_res;
        char log_f[MAX_FIELD_LEN];
        char log_num[20];
        char buffer[MAX_FIELD_LEN];
        int log = 0;
        char *web_root = NULL;
        free((int*)new_socket);

        memset(details,'\0',100);
	if(fcntl(socket_desc, F_SETFL, fcntl(socket_desc, F_GETFL) | O_NONBLOCK) < 0)
        {
                perror("\nerror setting socket in non blocking mode\n");
        }
        else
        {
                printf("\nYour socket is non blocking\n");
        }
        if (FAILURE == peer_addr(socket,details,MAX_FIELD_LEN))
        {
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
                        serve(socket,&http_res,buffer);
                }
                //printf("\nfinished serve function\n");
                printf("\nServed client %s\n",details);
        //      thread_count--;
        }

//close(socket);
pthread_detach(pthread_self());
pthread_exit(NULL);
}
