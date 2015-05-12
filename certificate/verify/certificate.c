
#include "common.h"

#define MODULUS_SIZE 2048
#define EXPONENT RSA_F4
#define CALLBACK_FN NULL
#define CALLBACK_ARG NULL


/*
 *	Certificate signing request is a message sent from an applicant
 *	to a certificate authority.
 */

void initOpenSSL(void)
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSL_library_init();
}


int verify(X509 *root_cert, X509 *user_cert)
{
	
	const char *errstr ;

	/*
	 *	In order to verify the certificates presented by the peer, trusted CA
	 *	certificates must be accessed.These CA certificates are made available
	 *	via lookup methods,handle inside the X509_STORE.From the X509_STORE the
	 *	X509_STORE_CTX used when verifying certificates is created.
	 */
	
	X509_STORE *ctx = NULL;
	
	/*
	 *	Structure required for X509_verify_cert
	 */
	X509_STORE_CTX *csc;

	int certstatus;

	ctx = X509_STORE_new();


	X509_STORE_add_cert(ctx, root_cert);

	/*
	 *	Create the context to verify the certificate
	 */
	csc = X509_STORE_CTX_new();

	/*
	 *	Initialize the store to verify the certificate
	 */
	X509_STORE_CTX_init(csc, ctx, user_cert, NULL);

	/*
	 *	Attempts to discover and validate a certificate chain based on the
	 *	parameters passed in csc.
	 */

	certstatus = X509_verify_cert(csc);

	if (certstatus != 1) {
		errstr = X509_verify_cert_error_string(csc->error);
		printf("Error in String:%s\n",errstr);
	}

	X509_STORE_CTX_cleanup(csc);
	X509_STORE_CTX_free(csc);
	X509_STORE_free(ctx);
	return certstatus;
}

int main(int argc, char *argv[])
{

	FILE *fp1 = fopen("cert_sign.pem", "r");

	FILE *fp2 = fopen("root.pem", "r");

	X509 *root, *requestor;

	initOpenSSL();

	/*
	 *	PEM_read_X509 converts the file pointer
	 *	specified into X509 format
	 */
	requestor = PEM_read_X509(fp1, NULL, 0, NULL);

	root = PEM_read_X509(fp2, NULL, 0, NULL);

	if (verify(root, requestor))
		printf("Successfully Verified\n");
	else
		printf("Not Verified:Fail\n");	

	return 0;
}
