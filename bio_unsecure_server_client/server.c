
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <pthread.h>

void error(char *msg)
{
	
	fprintf(stderr,"%s\n",msg);
	ERR_print_errors_fp(stderr);
	abort();
}


void server_thread(void *arg)
{
	char buf[80] = "Hello World Come Again";
	int value;
	BIO *client = (BIO *)arg;
	pthread_detach(pthread_self());
	printf("\n%s\n",__func__);
	do{
		int err = BIO_write(client, buf, sizeof(buf));
		if (err <= 0)
			break;
		err = BIO_read(client, &value, sizeof(int));
		if (err <= 0)
			break;
		fprintf(stdout, "value received from client:%d", value);
	}while(0);
	BIO_free(client);
}


void init_OpenSSL(void)
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
}

int main(int argc, char *argv[])
{

	BIO *server, *client;
	SSL *ssl;
	SSL_CTX *ctx;
	pthread_t tid;

	init_OpenSSL();

	/*
	 *	It creates a new accept BIO with port host_port
	 */
	server = BIO_new_accept("9104");

	if (!server)
		error("Error creating server socket");

	/*
	 *	BIO_do_accept() serves two functions. When it is first called, after the accept
	 *	BIO has been setup, it will attempt to create the accept socket and bind an 
	 *	address to it. Second and subsequent calls to BIO_do_accept() will await an
	 *	incoming connection,or request a retry in non blocking mode
	 */
	if (BIO_do_accept(server) <= 0)
		error("Setup BIO in Accepting Mode\n");
	for (;;)
	{
		if (BIO_do_accept(server) <= 0)
			error("Error Accepting Connection\n");
		/*
		 * When a connection is established a new socket BIO is created for the 
		 * connection and appended to the chain.
		 * BIO_pop removes the BIO b from a chain and returns the next BIO in the
		 * chain.
		 */
		client = BIO_pop(server);
		/*
		 *Now client here is containing a BIO for the recently established connection
		 *and server will now be a single BIO again which can be used to await further
		 *incoming connections
		 */
		pthread_create(&tid, NULL, (void *)server_thread, client);
	}
	/*
	 *	Close the connection
	 */
	BIO_free(server);
	return 0;
}
