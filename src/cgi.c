#include <stdio.h>
#include <mysql.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#define MAX_RCV_MSG_SIZE 8000
#define SUCCESS 0
#define FAILURE 1
#define LOGIN_FAILURE 2
#define QUERY_SIZE 500
#define PUT 1
#define POST 2
static unsigned long next;

/* RAND_MAX assumed to be 32767 */
int myrand(void) 
{
	next = next * 1103515245 + 12345;
        return((unsigned)(next/65536) % 32768);
}

struct tm*get_current_time()
{
        time_t rawtime;
        struct tm * timeinfo;
        time (&rawtime);
        timeinfo = localtime (&rawtime);

return timeinfo;
}

char *replace(char *s, char old, char new)
{
	char *p = s;

	while(*p!='\0')
	{
		if(*p == old)
		*p = new;
		++p;
	}
}
int parse_user_pwd(char *msg,char *user,char *passwd,char **usr)
{
int i = 0;
	if ((*usr = strstr(msg,"--user:"))!=NULL)
	{
		(*usr) += 7;
		while (**usr != ' ')	
		{
			user[i]=**usr;
			(*usr)++;
			i++;
		}	
	}
	else
	{
		return FAILURE;
	}
	i = 0;
	if ((*usr = strstr(*usr,"--password:"))!=NULL)
	{
		(*usr)+=11;
		while (**usr != ' ')
		{
			passwd[i]=**usr;	
			(*usr)++;
			i++;
		}
	}
	else
	{
		return FAILURE;
	}
return SUCCESS;
}
int file_permissions(char * filename)
{
    char qry[QUERY_SIZE];
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;
    char *server = "10.203.161.26"; /*database server address*/
    char *user = "root"; /*default user name for database*/
    char *password = "abc123"; /* default password for database*/
    char *database = "webserver"; /*Database name*/
    conn = mysql_init(NULL);
     /* Connect to database */
    if (!mysql_real_connect(conn, server,user, password, database, 0, NULL, 0))
    {

        return FAILURE;
    }
    sprintf(qry,"select * from pages where url = '%s'",filename);
    /* send SQL query */
    if (mysql_query(conn, qry))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(FAILURE);
    }
    res = mysql_use_result(conn);
    /* output table name */
    row = mysql_fetch_row(res);
    if (0 >= row) /*if user name doesn't exist*/
    {
        return SUCCESS;
    }
    else
    {
	return FAILURE;
    }
return SUCCESS;
}
int http_authentication(char* user_name, char* pass_word)
{
    char qry[QUERY_SIZE];
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;
    char *server = "10.203.161.26"; /*database server address*/
    char *user = "root"; /*default user name for database*/
    char *password = "abc123"; /* default password for database*/
    char *database = "webserver"; /*Database name*/
    conn = mysql_init(NULL);
     /* Connect to database */
    if (!mysql_real_connect(conn, server,user, password, database, 0, NULL, 0))
    {

        return FAILURE;
    }
    sprintf(qry,"select * from mywebserver where user = '%s'",user_name);
    /* send SQL query */
    if (mysql_query(conn, qry))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(FAILURE);
    }
    res = mysql_use_result(conn);
    /* output table name */
    row = mysql_fetch_row(res);
    if (0 >= row) /*if user name doesn't exist*/
    {
        return FAILURE;
    }
    else
    {
        /*if user name exist check the password*/
        if ((strcmp(user_name, row[0]) == 0) && (strcmp(pass_word, row[1]) == 0))
        {
            mysql_free_result(res);
            mysql_close(conn);
            return SUCCESS;
        }
        else if((strcmp(user_name, row[0]) == 0) && (strcmp(pass_word, row[1]) != 0) ) /*Incorrect Password*/
        {
                mysql_free_result(res);
                mysql_close(conn);
                return LOGIN_FAILURE;
        }
    }
return SUCCESS;
}
int main(void)
{
char *lenstr = NULL;
char *script = NULL;
char *method = NULL;
char msg[MAX_RCV_MSG_SIZE];
char *input = NULL;
long len = 0;
char root_path[1000];
char temp[1000];
FILE *f;
int log = 0;
char username[100];
char passwd[100];
int putpost = 0;
	script = getenv("SCRIPT_FILENAME");
	//printf("\nscript file name %s\n",script);
	printf("%s%c%c\n","Content-Type:text/html;charset=iso-8859-1",13,10);
	printf("<TITLE>Response</TITLE>\n");
	fflush(stdout);

	lenstr = getenv("CONTENT_LENGTH");
	script = getenv("SCRIPT_FILENAME");
	method = getenv("REQUEST_METHOD");
	if (strstr(method,"PUT") != NULL)
	{
		putpost = 1;
	}
	else
	{
		putpost = 2;
	}
	if(lenstr == NULL)
	{
	 	printf("<P>Error in invocation - wrong FORM probably</P>");
		fflush(stdout);
		exit(SUCCESS);
	}
	else 
	{
		if (1 != sscanf(lenstr,"%ld",&len))
		{
		 	printf("<P>Error in invocation - unknown content length</P>");	
			fflush(stdout);
			exit(SUCCESS);
		}
		else
		{
			memset(msg,'\0',MAX_RCV_MSG_SIZE);
		  	fgets(msg,MAX_RCV_MSG_SIZE, stdin);
			//printf("\n%s\n",input);
			//printf("\nmethod %s\n",method);
			memset(username,'\0',100);
			memset(passwd,'\0',100);


			f = fopen("./conf","r");
			if (NULL == f)
			{
				printf("<P>501 INETRNAL SERVER ERROR</P>");
				fflush(stdout);
				exit(SUCCESS);
			}
			memset(root_path,'\0',1000);
			fgets(root_path,1000,f);
			//printf("\nroot path %s\n",root_path);
			fclose(f);
			root_path[strlen(root_path) - 1] = '\0';
			if (putpost == POST)
			{	
				//printf("its a post method");
				sprintf(temp,"%s",asctime(get_current_time()));
				replace(temp,'\n','_');
				replace(temp,' ','_');
				replace(temp,':','_');
				strcat(root_path,"/WEB/post/");
				strcat(root_path,temp);
				sprintf(temp,"%d",myrand());
				strcat(root_path,temp);
				strcat(root_path,".txt");
				f = fopen(root_path, "w+");
				if(f == NULL)
				{
					printf("<P>Sorry, cannot store your data.</P>");
					fflush(stdout);
				}
				else
				{
					fputs(input, f);
					fclose(f);
					f = fopen("./conf","r");
					fgets(temp,1000,f);
		  			fclose(f);
					printf("<P>YOUR DATA HAS BEEN SUBMITED AND THE URL IS /post/%s</P>",root_path+strlen(temp));
					fflush(stdout);
				}
				exit(SUCCESS);
			}	
					//printf("its a put method");

			if ((parse_user_pwd(msg,username,passwd,&input)== SUCCESS))
			{
				if ((http_authentication(username,passwd) == SUCCESS))
				{	
					if (putpost == PUT && file_permissions(script)==FAILURE)	
					{
						printf("<P>FILE PERMISSIONS ARE RESTRICTING YOU</P>");
						fflush(stdout);
						exit(FAILURE);
					}
					if(putpost == PUT)
					{
						if (script[strlen(script)-1]=='/')
						{
							printf("<P>204 NOT FOUND</P>");
						}
						if (strstr(script,"php") == NULL)
						{
							strcpy(root_path,script);
							//printf("\nput script %s\n",script);
							strcpy(temp,script);
							f = fopen(root_path, "w+");
							if(f == NULL)
							{
							    	printf("<P>Sorry, cannot store your data.</P>");
								fflush(stdout);
								exit(FAILURE);
							}
							else
							{
								fputs(input, f);
								fclose(f);
								f = fopen("./conf","r");
								fgets(root_path,1000,f);
								printf("<P>YOUR DATA  HAS BEEN SUBMITED AND THE URL IS /%s</P>",temp + strlen(root_path) + 5);
								fflush(stdout);
								fclose(f);
								exit(FAILURE);
							}
						}
						else
						{
							printf("<P>PHP PAGES ARE NOT SUPPORTED DUE TO SECURITY REGULATIONS </P>");
							fflush(stdout);
						}
					}
					else
					{
						printf("<P>UNKNOWN METHOD</P>");
						exit(FAILURE);
					}
				}	
				else
				{
					printf("<P>YOU ARE NOT THE AUTHORIZED USER TO USE PUT REQUESTS please provide user name and passwd</P>",username,passwd);
					printf("<P>USAGE --user:username --password:password</P>");
					fflush(stdout);
				}
			}
			else
			{	
				printf("<P>Parsing error</P>");
				printf("<P>YOU %s  ARE NOT THE AUTHORIZED USER TO USE PUT REQUESTS please provide user name and passwd</P>",username,passwd);
				printf("<P>USAGE --user:username --password:password</P>");
			}
		}
	}
exit(SUCCESS);
}
