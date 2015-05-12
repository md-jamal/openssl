





#include "common.h"

#define MODULUS_SIZE 2048
#define EXPONENT RSA_F4
#define CALLBACK_FN NULL
#define CALLBACK_ARG NULL


void initOpenSSL(void)
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSL_library_init();
}


EVP_PKEY * generate_PrivateKey(void)
{
	
	EVP_PKEY *pkey;
	RSA *rsa;

	/*Allocates an empty EVP_PKEY structure*/
	pkey = EVP_PKEY_new();

	/*Generates a Key Pair and returns in a newly allocated RSA structure*/
	rsa = RSA_generate_key(MODULUS_SIZE, EXPONENT, CALLBACK_FN, CALLBACK_ARG);

	/*If key generation fails , RSA_generate_key returns NULL*/

	if (!rsa) {
		printf("Error: %ld\n", ERR_get_error());
		return NULL;
	}

	/*Assigns rsa to pkey*/
	if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
		printf("Error:%ld\n", ERR_get_error());
		return NULL;
	}
	return pkey;
}

int main(int argc, char *argv[])
{
	

	FILE *fp = fopen("hello.pem", "w");

	/*EVP_PKEY is a structure used by openssl to store private keys*/
	EVP_PKEY *root_pkey;

	initOpenSSL();

	/*Generate a private key for root CA*/
	root_pkey = generate_PrivateKey();

	/*Printing it on the stdout*/
	PEM_write_PrivateKey(stdout, root_pkey, NULL, NULL, 0, 0, NULL);

	PEM_write_PrivateKey(fp, root_pkey, NULL, NULL, 0, 0, NULL);
	

	/*Free the allocated EVP_PKEY structure*/
	EVP_PKEY_free(root_pkey);

	return 0;
}
