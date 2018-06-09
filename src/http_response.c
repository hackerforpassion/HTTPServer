/********************************************************************************
                                FILE HEADER
* NAME : head_response.c

* DESCRIPTION : Contains function descriptions.

* DATE          AUTHOR          REFERENCE               PURPOSE

********************************************************************************/
#include<server.h>
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
/******************************************************************************
                                FUNCTION HEADER
* NAME : create_http_head_response_pack

* DESCRIPTION : Creates HTTP head response packet

* RETURN : int

******************************************************************************/

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
/******************************************************************************
                                FUNCTION HEADER
* NAME : create_http_head_response_pack

* DESCRIPTION : Creates HTTP head response packet

* RETURN : int

******************************************************************************/

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
/******************************************************************************
                                FUNCTION HEADER
* NAME : create_http_head_response_pack

* DESCRIPTION : Creates HTTP head response packet

* RETURN : int

******************************************************************************/

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

/******************************************************************************
                                FUNCTION HEADER
* NAME : create_http_head_response_pack

* DESCRIPTION : Creates HTTP head response packet

* RETURN : int

******************************************************************************/

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
/******************************************************************************
                                FUNCTION HEADER
* NAME : create_http_head_response_pack

* DESCRIPTION : Creates HTTP head response packet

* RETURN : int

******************************************************************************/

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
