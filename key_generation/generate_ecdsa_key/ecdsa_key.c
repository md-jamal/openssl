





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
	EC_KEY *eckey;

	/*Allocates an empty EVP_PKEY structure*/
	pkey = EVP_PKEY_new();

	/*openssl ecparam -list_curves*/
	eckey = EC_KEY_new_by_curve_name(NID_secp256k1);

	if (!eckey) {
		printf("error in new ec_key\n");
		abort();
	}

	if (!EC_KEY_generate_key(eckey)) {
		printf("Error: %ld\n", ERR_get_error());
		return NULL;
	}

	/*Assigns eckey to pkey*/
	if (EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) {
		printf("Error:%ld\n", ERR_get_error());
		return NULL;
	}
	return pkey;
}

int main(int argc, char *argv[])
{

	FILE *fp = fopen("ecdsa.pem", "w");

	FILE *fp1 = fopen("ecdsa_pub.pem", "w");

	/*EVP_PKEY is a structure used by openssl to store private keys*/
	EVP_PKEY *root_pkey;

	initOpenSSL();

	/*Generate a private key for root CA*/
	root_pkey = generate_PrivateKey();

	/*Printing it on the stdout*/
	PEM_write_PrivateKey(stdout, root_pkey, NULL, NULL, 0, 0, NULL);

	PEM_write_PUBKEY(stdout, root_pkey);

	/*Copying private key on the file */
	PEM_write_PrivateKey(fp, root_pkey, NULL, NULL, 0, 0, NULL);

	/*Copying public key on the file */
	PEM_write_PUBKEY(fp1, root_pkey);

	/*Free the allocated EVP_PKEY structure*/
	EVP_PKEY_free(root_pkey);

	return 0;
}
