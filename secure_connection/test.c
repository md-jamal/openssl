
/*
 *gcc test.c -lcrypto -lssl
 */

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"

#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>


#define FAIL -1

struct addrinfo *res;

//This function performs nslookup operation converts domain name to IP Address
struct sockaddr_in * getByName(const char *name)
{
	
	struct addrinfo hints;
	struct  addrinfo  *p;
	char ipstr[INET6_ADDRSTRLEN];
	int status;

	bzero(&hints, sizeof(hints));	//Making sure that the structure is empty
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(name, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo error:%s\n", gai_strerror(status));
		exit(1);
	}

	for (p = res; p != NULL; p = p->ai_next) {
		void *addr;
		
		if (p->ai_family == AF_INET) {
			return (struct sockaddr_in *)p->ai_addr;
		}
	}
	return NULL;
}


int OpenConnection(const char *hostname, int port)
{
	
	int fd;
	struct sockaddr_in addr;
	struct sockaddr_in *result = getByName(hostname) ;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr = result->sin_addr;
	//`inet_aton(hostname, &addr.sin_addr);
	//addr.sin_addr.s_addr = *(long *)(host->h_addr);

	if( connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		close(fd);
		perror(hostname);
		abort();
	}
	return	fd;	
}



SSL_CTX *InitCTX(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	//This will load all the encryption and digest algorithms
	OpenSSL_add_all_algorithms();
	//Registers the libssl error strings and the error strings for all libcrypto functions.This is called when you want to generate textual error messages.
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	//As we are using SSL V3 protocol we will using this method.This depends on the message you are using
	method = SSLv3_client_method();
	ctx = SSL_CTX_new(method);

	if (ctx == NULL) {
		//This function prints the error strings for all errors that OpenSSL has recorded on the stderr file
		ERR_print_errors_fp(stderr);
		//It is c library function that will abort the program execution and comes out directly from the place of the call
		abort();
	}
	return ctx;
}


void ShowCerts(SSL *ssl)
{
	
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);	/*Get the Server's Certificate*/

	if ( cert != NULL)
	{
		printf("Server Certificates:\n");

		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);	/*free the malloc'ed string*/

		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);	/*free the malloc'ed string*/

		X509_free(cert); /*free the malloc'ed certificate*/	
	}
	else
		printf("No Certificate\n");
}



int main(int argc, char *argv[])
{

	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	
	if (argc != 3)
	{
		printf("Usage :%s <hostname> <portnum>\n",argv[0]);
		exit(0);
	}

	/*Initialize the library */
	SSL_library_init();//SSL_library_init() registers the available SSL/TLS ciphers and digests.

	ctx = InitCTX();

	server = OpenConnection(argv[1], atoi(argv[2]));

	/*
	 *	SSL_new() creates a new SSL structure which is needed to hold the data for a TLS/SSL 
	 *	connection.The new structure inherits the settings of the underlying context ctx:
	 *	connection method, options, verification settings,timeout settings
	 */
	ssl = SSL_new(ctx);

	/*
	 *	connect the SSL Object with a socket file descriptor
	 */
	SSL_set_fd(ssl, server);

	/*
	 *	Initiates the TLS/SSL handshake with the server.
	 *
	 */

	if ( SSL_connect(ssl) == FAIL)
		ERR_print_errors_fp(stderr);
	else
		ShowCerts(ssl);

	close(server);
	SSL_CTX_free(ctx);
	freeaddrinfo(res);
	return 0;	
}
