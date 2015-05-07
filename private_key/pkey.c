


#include <stdio.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

/*
 *	Program displays the private key on stdout
 *
 *
 */

void initOpenSSL(void)
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSL_library_init();
}





int main(int argc, char *argv[])
{
	
	/*
	 *EVP_PKEY is used to store private keys
	 */
	EVP_PKEY *ca_pkey;

	FILE *fp;

	initOpenSSL();
	/*
	 *	EVP_PKEY_new() fn allocates an empty EVP_PKEY structure
	 */
	ca_pkey = EVP_PKEY_new();

	
	fp = fopen("cakey.pem", "r");

	PEM_read_PrivateKey(fp, &ca_pkey, NULL, NULL);
	
	fclose(fp);

	PEM_write_PrivateKey(stdout, ca_pkey, NULL, NULL, 0, 0, NULL);

	return 0;
}
