
#include "common.h"

void initOpenSSL(void)
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSL_library_init();
}

int main(int argc, char *argv[])
{


	X509_REQ *x509;
	/*EVP_PKEY is a structure used by openssl to store private keys*/
	EVP_PKEY *root_pkey;
	FILE *fp;

	if (argc != 2) {
		printf("\nHelp:<EXE> <file.csr>\n");
		exit(1);
	}

	initOpenSSL();
	fp = fopen(argv[1], "rb");
	if (fp == NULL) {
		perror("Error in fopen\n");
		exit(1);
	}
	
	x509 = PEM_read_X509_REQ(fp, NULL, 0, NULL);	
	root_pkey = X509_REQ_get_pubkey(x509);

	if (root_pkey == NULL) {
		printf("No Public Key Found\n");
		goto err;
	}

	if (X509_REQ_verify(x509, root_pkey) == -1) {
		printf("Verification failed:%d\n", X509_REQ_verify(x509, root_pkey));
		ERR_print_errors_fp(stderr);
		goto err;
	}
	printf("Verification Successful:%d\n", X509_REQ_verify(x509, root_pkey));
	
	return 0;

err:	return 1;
}
