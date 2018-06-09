#include <stdio.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <mysql.h>
#include <stdlib.h>
#define SUCCESS 0
#define FAILURE 1
#define RUN_SERVER 1
#define STOP_SERVER 2
#define EXIT_MONITOR 3
#define EXIT_ADMIN 4
#define ERROR -1
#define QUERY_SIZE 500
#define NAME_LENGTH 200
int *status = NULL;
int *control = NULL;
int admin = 1;
int add_user(char * user_name,char *pass_word)
{
    char qry[QUERY_SIZE];
    MYSQL *conn;
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
    sprintf(qry,"insert into users values('%s','%s')",user_name,pass_word);
    /* send SQL query */
    if (mysql_query(conn, qry))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return FAILURE;
    }
return SUCCESS;
}
int rm_user(char * user_name)
{
    char qry[QUERY_SIZE];
    MYSQL *conn;
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
    sprintf(qry,"delete from users where user = '%s'",user_name);
    /* send SQL query */
    if (mysql_query(conn, qry))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return FAILURE;
    }
return SUCCESS;
}
int allow_file(char * filename)
{
    char qry[QUERY_SIZE];
    MYSQL *conn;
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
    sprintf(qry,"insert into pages values('%s')",filename);
    /* send SQL query */
    if (mysql_query(conn, qry))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return FAILURE;
    }
return SUCCESS;
}
int display_users()
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
    sprintf(qry,"select * from users");
    /* send SQL query */
    if (mysql_query(conn, qry))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return FAILURE;
    }
    res = mysql_use_result(conn);
    /* output table name */
    printf("\n_______________________________________________________\n");
    while ((row = mysql_fetch_row(res)))
    {
        printf("\nuser name:%s\n",row[0]);
    }
    printf("\n_______________________________________________________\n");
    if (0 >= row)
    {
        return SUCCESS;
    }
    else
    {
        return FAILURE;
    }
return SUCCESS;
}
int display_files()
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
    sprintf(qry,"select * from pages");
    /* send SQL query */
    if (mysql_query(conn, qry))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return FAILURE;
    }
    res = mysql_use_result(conn);
    /* output table name */
    printf("\n_______________________________________________________\n");  
    while ((row = mysql_fetch_row(res)))
    {
	printf("\nfile name:%s\n",row[0]);
    }
    printf("\n_______________________________________________________\n");  
    if (0 >= row) 
    {
        return SUCCESS;
    }
    else
    {
        return FAILURE;
    }
return SUCCESS;
}
int restrict_file(char * filename)
{
    char qry[QUERY_SIZE];
    MYSQL *conn;
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
    sprintf(qry,"delete from pages where url='%s'",filename);
    /* send SQL query */
    if (mysql_query(conn, qry))
    {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return FAILURE;
    }
return SUCCESS;
}

void stop_server()
{
	*control = STOP_SERVER;
}
void start_server()
{
	*control = RUN_SERVER;
}
void exit_monitor()
{
	*control = EXIT_MONITOR;
}
void exit_admin()
{
	*control = EXIT_MONITOR;
	admin = 0;
}
int init_shared_memory(int **shared_memory,key_t shm_key,int *segment_id)
{
  const int shared_segment_size = 0x04;
  /* Allocate a shared memory segment. */
  *segment_id = shmget (shm_key, shared_segment_size,
            IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
  if (ERROR == *segment_id)
  {
	perror("\nError getting shared memory\n");
	exit(FAILURE);
  }
  /* Attach the shared memory segment. */
  *shared_memory = (int*) shmat (*segment_id, 0, 0);
  if (*shared_memory == NULL)
  {
	perror("\nUnable to create a communicating ipc object\n");
	exit(FAILURE);
  }
return SUCCESS;
}
int main (int argc,char *argv[])
{
  char file_name[NAME_LENGTH];
  char user_name[NAME_LENGTH];
  char pass_word[NAME_LENGTH];
  int segment_id1;
  int segment_id2;
  int option = -1;
  init_shared_memory(&control,'u',&segment_id1);
  init_shared_memory(&status,'i',&segment_id2);
  *control = STOP_SERVER;
  *status = -1;
  while(admin)
  {
	printf("\n1)start server\n");
	printf("\n2)stop server\n");
	printf("\n3)EXIT MONITOR\n");
	printf("\n4)exit admin\n");
	printf("\n5)rm file restriction\n");
	printf("\n6)add file restriction\n");
	printf("\n7)add user\n");
	printf("\n8)delete user\n");
	printf("\n9)display restricted files\n");
	printf("\n10)display users\n");
	
	scanf("%d",&option);
	switch(option)
	{
		case 1:
			if (*control != EXIT_MONITOR && *status != -1)
			{
				if (*control != RUN_SERVER)
				{
					start_server();
					printf("\nstarting the server\n");
				}
				else 
				{
					printf("\nserver is already running\n");
				}
			}
			else 
			{
				printf("\nmonitoring progrm is not running\n");
			}
			break;
		case 2:
			if (*control != EXIT_MONITOR && *status != -1)
			{
				if (*control != STOP_SERVER)
				{
					stop_server();
					printf("\nstopping the server\n");
				}
				else 
				{
					printf("\nserver is not  running\n");
				}
			}
			else 
			{
				printf("\nmonitoring progrm is not running\n");
			}
			break;
		case 3:
			if (*control != EXIT_MONITOR && *status != -1)
			{
				printf("\nMonitoring program is exiting\n");
				exit_monitor();
			}
			else
			{
				printf("\nmonitor is not running or already stopped\n");
			}
			break;
		case 4:
			if (*control != EXIT_MONITOR && *status != -1)
			{
				printf("\nFirst exit the server\n");
			}
			else
			{
				exit_admin();
			}
			break;
		case 5:
			printf("\nEnter the file name you want to remove restriction\n");
			scanf("%s",file_name);
			if (FAILURE == restrict_file(file_name))
			{
				perror("\nFAILED to delete an entry\n");
			}
			else
			{
				printf("\nDatabase updated\n");
			}
			break;
		case 6:
			printf("\nEnter the file name you want to add restriction\n");
			scanf("%s",file_name);
			if (FAILURE == allow_file(file_name))
			{
				perror("\nFAILED to update an entry\n");
			}
			else
			{
				printf("\nDatabase updated\n");
			}
			break;
		case 7:
			printf("\nEnter the user name and password to add\n");
			scanf("%s%s",user_name,pass_word);
			if (FAILURE == add_user(user_name,pass_word))
			{
				perror("\nFAILED to add user\n");
			}
			else
			{
				printf("\nDatabase updated\n");
			}
			break;
		case 8:
			printf("\nEnter the user name to delete\n");
			scanf("%s",user_name);
			if (FAILURE == rm_user(user_name))
			{
				perror("\nFAILED to delete the user\n");
			}
			else
			{
				printf("\nDatabase updated\n");
			}
			break;
		case 9:
			if (FAILURE == display_files())
			{
				perror("\nerror printing file names\n");
			}
			else
			{
				printf("\nquery successful\n");
			}
			break;
		case 10:
			if (FAILURE == display_users())
			{
				perror("\nerror printing user names\n");
			}
			else
			{
				printf("\nquery successful\n");
			}
			break;
		default:
			printf("\nEnter a valid option\n");
	}
  }
  *control = EXIT_MONITOR;
  printf("\nServer stopped\n");
  /* Detach the shared memory segment. */
  shmdt (control);
  shmdt (status);
  /* Deallocate the shared memory segment.*/
  shmctl (segment_id1, IPC_RMID, 0);
  shmctl (segment_id2, IPC_RMID, 0);

exit(SUCCESS);
}
