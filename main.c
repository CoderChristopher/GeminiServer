#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <signal.h>

#define STD_BUFFER_SIZE 1027
#define STD_REQUEST_SIZE 1027
#define DEBUG_MODE 1

bool done=false;
int fulfilled=0;

void sigterm(int sigval){
	done=true;
}
void siginfo(int sigval){
	printf("Fulfilled:%i\n",fulfilled);
}

//Allows for general error reporting on sockets and their associated functions
void checkerror(const char* message, int condition, int sock){
	if( condition == -1){
		printf("***%s\n",message);
		printf("***Socket: %i\n",sock);
		printf("\t%i:%s\n",errno,strerror(errno));
		exit(-1);
	}
}

void initssl(){
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
}

void destroyssl(){
	ERR_free_strings();
	EVP_cleanup();
}
void shutdownssl(SSL* cSSL){
	SSL_shutdown(cSSL);
	SSL_free(cSSL);
}
int getresource(char* resourcedestination, char* resourcesource){
	if(!resourcedestination||!resourcesource){
		return -1;
	}
	char* resource=strtok(resourcesource," \r\n");
	strcpy(resourcedestination,resource);
	if(resourcedestination==NULL)
		return -1;
	return 0;
}
int getpage(char* pagedestination, char* resourcesource){
	strcpy(pagedestination,"main.c");
	if(!pagedestination||!resourcesource){
		return -1;
	}
	char* st	= NULL;
	char* buffer 	= malloc(STD_BUFFER_SIZE);
	memset(buffer,0,STD_BUFFER_SIZE);
	strcpy(buffer,resourcesource);
	if((st=strstr(resourcesource,"gemini://"))){
		strcpy(buffer,&st[9]);
	}
	char* page = strtok(buffer,"/");
	if(page==NULL){
		return -1;
	}
	page=strtok(NULL,"/");
	if(page==NULL){
		return -1;
	}
	strcpy(pagedestination,page);
	while((page=strtok(NULL,"/"))){
		strcat(pagedestination,"/");
		strcat(pagedestination,page);
	}
	free(buffer);
	return 0;
}
int sanitizecheck(char* pagesource){
	if(!pagesource){
		return -1;
	}
	if(strstr(pagesource,"..")){
		if(DEBUG_MODE)
			printf("**SANITZER '..' found!\n");
		return 1;
	}
	return 0;
}

int main(int argc,void * argv[]){
	
	signal(SIGTERM,sigterm );
	signal(SIGUSR1,siginfo );

	int sock   = -1;
	int insock = -1;
	int option =  1;
	int error  = -1;

	SSL_CTX *sslctx;
	SSL *cSSL;

	char* inbuffer  = malloc(STD_REQUEST_SIZE);
	char* outbuffer = NULL;
	char* resource 	= malloc( STD_BUFFER_SIZE);
	char* page 	= malloc( STD_BUFFER_SIZE);
	char* indicator = malloc( STD_BUFFER_SIZE);

	memset( inbuffer, 0, STD_REQUEST_SIZE);
	memset( resource, 0,  STD_BUFFER_SIZE);
	memset(     page, 0,  STD_BUFFER_SIZE);
	memset(indicator, 0,  STD_BUFFER_SIZE);
	
	struct sockaddr    addrin;
	struct sockaddr_in addr;
	socklen_t	   socklen=0;

	addr.sin_family = AF_INET;
	addr.sin_port   = htons(1965);
	addr.sin_addr.s_addr= inet_addr("127.0.0.1");

	initssl();

	//Start setting up the low level sockets for the server.
	sock=socket( AF_INET, SOCK_STREAM, 0);
	checkerror("There was an error creating the socket!",sock,sock);

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

	error=bind( sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in));
	checkerror("There was an error in binding the socket!",error,sock);

	error=listen(sock, 10);
	checkerror("There was an error while listening on the socket!",error,sock);

	while(done==false){
		unsigned char status = 20;
		char* body = NULL;
		insock=accept(sock, &addrin, &socklen);
		checkerror("There was an error in accepting the connection!",insock,insock);

		if(DEBUG_MODE)
			printf("*New SSL Connection beginning...\n");
		//Begin the passoff to SSL
		sslctx = SSL_CTX_new(TLS_server_method());

		//Loadup the certificate and key
		int use_cert = SSL_CTX_use_certificate_file(sslctx, "cert.pem",SSL_FILETYPE_PEM);
		int use_prv  = SSL_CTX_use_PrivateKey_file(sslctx, "key.pem",SSL_FILETYPE_PEM);

		cSSL = SSL_new(sslctx);
		SSL_set_fd(cSSL,insock);
		int ssl_err=SSL_accept(cSSL);	
		if(ssl_err!=1){
			if(DEBUG_MODE)
				printf("There was an issue with the SSL_accept!\n");
			goto exit;
		}

		//Read in the standard response
		SSL_read(cSSL,inbuffer,STD_REQUEST_SIZE);
		if(getresource(resource,inbuffer)){
			status=50;
			if(DEBUG_MODE)
				printf("*Resource was empty...\n");
			strcpy(indicator,"No resource was given.");	
		}
		if(!strcmp(resource,"/")){
			if(DEBUG_MODE)
				printf("*/ directory given...\n");
			//Load default page
			strcpy(page,"index.gmi");
		}else if(!strcmp(resource," ")){
			if(DEBUG_MODE)
				printf("*no directory given...\n");
			//Load default page
			strcpy(page,"index.gmi");
		}else {
			if(DEBUG_MODE)
				printf("*Directory given: %s\n",resource);
			getpage(page,resource);
		}
		if(DEBUG_MODE)
			printf("*Page Requested: %s\n",page);

		//Sanatize
		if(sanitizecheck(page)!=0){
			status=50;
			strcpy(indicator,"Sanitization check of URI failed.");	
		}

		ssize_t filelength=0;
		FILE* file=fopen(page,"r");		
		if(!file){
			status=51;
			//Hmmm maybe an opportunity for some hacker to do a buffer overflow?
			//>:D (Will fix)
			sprintf(indicator,"Page %s not found!",page);
		}else{
			fseek(file, 0, SEEK_END);
			ssize_t filelength = ftell(file);
			fseek(file, 0, SEEK_SET);
			body=malloc(filelength+1);
			fread(body, 1, filelength,file);
			body[filelength] = 0;
			fclose(file);
		}

		size_t outbuffersize=0;
		//Respond with the standard success response.
		if(body){
			//Another opportunity for a buffer overflow. May this code never see
			//the light of production
			outbuffersize=5+2+strlen(indicator)+strlen(body);
			outbuffer=malloc(outbuffersize);
			sprintf( outbuffer, "%i %s\r\n%s\r\n", status, indicator, body);
			memset( body, 0, filelength);
			free(body);
		}else{
			outbuffersize=3+2+strlen(indicator);
			outbuffer=malloc(outbuffersize);
			sprintf( outbuffer, "%i %s\r\n", status, indicator);
		}
		if(DEBUG_MODE)
			printf("*Sending a response with a status code %i.\n",status);
		if(outbuffer)
			SSL_write(cSSL,outbuffer,outbuffersize);

		free(outbuffer);
		outbuffer=NULL;
		
		exit:;
		//And close the session
		shutdownssl(cSSL);

		error=shutdown( insock, SHUT_RDWR);
		checkerror("There was an error shutting down the input socket!",error,sock);
		memset( resource, 0, STD_BUFFER_SIZE);
		memset(     page, 0, STD_BUFFER_SIZE);
		memset( inbuffer, 0,STD_REQUEST_SIZE);
		memset(indicator, 0, STD_BUFFER_SIZE);
		fulfilled++;
	}

	if(DEBUG_MODE)
		printf("*Closing up shop...\n");

	free( resource);
	free(     page);
	free( inbuffer);
	free(indicator);


	destroyssl();
	
	error=shutdown( sock, SHUT_RDWR);
	checkerror("There was an error shutting down the socket!",error,sock);
	return 0;
}
