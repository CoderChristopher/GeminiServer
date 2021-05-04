#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define STD_BUFFER_SIZE 1024

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

int main(int argc,void * argv[]){
	int sock   = -1;
	int insock = -1;
	int option =  1;
	int error  = -1;

	SSL_CTX *sslctx;
	SSL *cSSL;

	char* inbuffer  = malloc(STD_BUFFER_SIZE);
	char* outbuffer = malloc(STD_BUFFER_SIZE);

	memset(inbuffer , 0, STD_BUFFER_SIZE);
	memset(outbuffer, 0, STD_BUFFER_SIZE);
	
	struct sockaddr    addrin;
	struct sockaddr_in addr;
	socklen_t	   socklen=0;

	addr.sin_family = AF_INET;
	addr.sin_port   = htons(1965);
	addr.sin_addr.s_addr= inet_addr("192.168.0.4");

	initssl();

	sock=socket( AF_INET, SOCK_STREAM, 0);
	checkerror("There was an error creating the socket!",sock,sock);

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

	error=bind( sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in));
	checkerror("There was an error in binding the socket!",error,sock);

	error=listen(sock, 10);
	checkerror("There was an error while listening on the socket!",error,sock);

	insock=accept(sock, &addrin, &socklen);
	checkerror("There was an error in accepting the connection!",insock,insock);

	sslctx = SSL_CTX_new(TLS_server_method());

	int use_cert = SSL_CTX_use_certificate_file(sslctx, "cert.pem",SSL_FILETYPE_PEM);
	int use_prv  = SSL_CTX_use_PrivateKey_file(sslctx, "key.pem",SSL_FILETYPE_PEM);

	cSSL = SSL_new(sslctx);
	SSL_set_fd(cSSL,insock);
	int ssl_err=SSL_accept(cSSL);	
	SSL_read(cSSL,inbuffer,1024);

	sprintf(outbuffer,"20 text/gemini\r\n %s\r\n","This is some body content.");
	SSL_write(cSSL,outbuffer,STD_BUFFER_SIZE);

	destroyssl();

	error=shutdown( sock, SHUT_RDWR);
	checkerror("There was an error shutting down the socket!",error,sock);
	return 0;
}
