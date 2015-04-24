#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


#include <stdio.h>
#include <string.h>


/*
 *	Eg: exe www.google.com:443
 */

SSL_CTX *OpenSSL_init(void)
{

	SSL_CTX *ctx;
	const SSL_METHOD *method;

	//Initialize the library
	SSL_library_init();

	//Load all the encryption and digestion algorithms
	OpenSSL_add_all_algorithms();

	//Register the libssl and libcrypto library error strings.Useful to generate textual error
	//messages
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	//Choose the client method
	method = TLSv1_client_method();
	ctx = SSL_CTX_new(method);

	if (ctx == NULL) {
		//print the error recorded by openssl
		ERR_print_errors_fp(stderr);
		
		//Terminate the program
		abort();
	}
	return ctx;
}

void ShowCerts(SSL *ssl)
{
	
	X509 *cert;
	char *line;

	/*
	 *	Returns the peer certificate that was received when the Secure Socket layer (SSL) 
	 *	session was started
	 */
	cert = SSL_get_peer_certificate(ssl);	/*Get the Server's Certificate*/

	if ( cert != NULL)
	{
		printf("Server Certificates:\n");

		/*
		 *	X509_Name_oneline prints an ascii version of first argument to
		 *	second argument(buf).If NULL is passed it dynamically allocates a 
		 *	buffer and returns it.
		 *
		 *	X509_get_subject_name and X509_get_issuer_name is used to get the 
		 *	subject and issuer name from the certificate
		 */
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);	/*free the malloc'ed string*/

		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);	/*free the malloc'ed string*/
		/*
		 *	It frees up the X509 structure
		 */
		X509_free(cert); /*free the malloc'ed certificate*/	
	}
	else
		printf("No Certificate\n");
}




int main(int argc, char *argv[])
{


	BIO *bio;
	SSL *ssl;
	SSL_CTX *ctx;

	if (argc != 2) {
		printf("Usage :%s <hostname> <portnumber>\n", argv[0]);
		exit(0);
	}

	ctx = OpenSSL_init();

	/* Load the trust store */
	if (! SSL_CTX_load_verify_locations(ctx, "cacert.pem", NULL)) {
		fprintf(stderr, "Error loading trusted store\n");
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		abort();
	}

	/*
	 *	Creates an BIO chain consisting of an SSL BIO(using ctx) followed by a connect BIO.
	 */
	bio = BIO_new_ssl_connect(ctx);
	
	/*
	 *	retrieves the SSL pointer of BIO b, that can be manipulated using the standard SSL
	 *	library functions.
	 */
	
	BIO_get_ssl(bio, &ssl);

	/*
	 * In case of nonblocking,this flag will cause read/write operations to only return after 
	 * the handshake and  successful operation
	 */

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	
	/*
	 *	It is used to set the hostname. The hostname can be IP Address.It can also 
	 *	include the port in the form hostname:port
	 */
	BIO_set_conn_hostname(bio, argv[1]);



	/*
	 *	BIO_do_connect() attempts to connect to the supplied BIO.It returns 1 when 
	 *	the connection was successfully satisfied.
	 */

	if (BIO_do_connect(bio) <= 0)
	{
		fprintf(stderr, "Error attempting to connect\n");
		ERR_print_errors_fp(stderr);
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
		abort();
	}

	/*Verify the certificates */

	if (SSL_get_verify_result(ssl) != X509_V_OK) {
		fprintf(stderr, "Certification Verification Error:%li\n",SSL_get_verify_result(ssl));
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
		abort();
	}
	ShowCerts(ssl);
	
	return 0;
}


