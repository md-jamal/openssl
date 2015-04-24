
/*
 *gcc test.c -lcrypto -lssl
 */

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"

#include <stdio.h>



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





int main(int argc, char *argv[])
{

	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	
	/*Initialize the library */
	SSL_library_init();//SSL_library_init() registers the available SSL/TLS ciphers and digests.

	ctx = InitCTX();

	return 0;	
}
