





#include "common.h"

#define MODULUS_SIZE 2048
#define EXPONENT RSA_F4
#define CALLBACK_FN NULL
#define CALLBACK_ARG NULL
#define SHA1_LEN 20

char input_data[128] = "Hello Iam going to be the data which will be encrypted";


void initOpenSSL(void)
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSL_library_init();
}


RSA*  generate_KeyPair(void)
{
	RSA *rsa;

	/*Generates a Key Pair and returns in a newly allocated RSA structure*/
	rsa = RSA_generate_key(MODULUS_SIZE, EXPONENT, CALLBACK_FN, CALLBACK_ARG);

	/*If key generation fails , RSA_generate_key returns NULL*/

	if (!rsa) {
		printf("Error: %ld\n", ERR_get_error());
		return NULL;
	}
	return rsa;
}


int main(int argc, char *argv[])
{

	RSA *rsa;
	char *encrypt_data;
	int siglen, i=0;

	initOpenSSL();

	rsa = generate_KeyPair();

	/*
	 *	int RSA_public_encrypt(int flen, unsigned char *from,
	 *				unsigned char *to, RSA *rsa, int padding);
	 *
	 *	RSA_public_encrypt() encrypts the flen bytes at from using the public
	 *	key rsa and stores the ciphertext in to.to must point to RSA_size(rsa)
	 *	bytes of memory
	 */

	encrypt_data = (char *)malloc(RSA_size(rsa));

	printf("Input Data:%s\n", input_data);

	if (RSA_public_encrypt(strlen(input_data), input_data,
				encrypt_data, rsa, RSA_PKCS1_PADDING) == -1)
		printf("Encryption Failed\n");

	memset(input_data, 0, sizeof(input_data));

	/*
	 *
	 *	int RSA_private_decrypt(int flen, unsigned char *from,
	 *				unsigned char *to, RSA *rsa, int padding);
	 *
	 *	RSA_private_decrypt decrypts the flen bytes at from using the
	 *	private keys rsa and stores the plain text in to. to must point
	 *	to a memory section large enough to hold the decrypted data.
	 */

	if (RSA_private_decrypt(RSA_size(rsa), encrypt_data, 
				input_data, rsa, RSA_PKCS1_PADDING) == -1)
		printf("Decryption Failed\n");

	printf("Encryption Data:\n");
	for (i = 0; i <2*RSA_size(rsa); i++) {
		if (i%2 == 0)
			printf("%02x", (encrypt_data[i/2]>>4)&0x0f);
		else 
			printf("%02x", (encrypt_data[i/2])&0x0f);
	}
	printf("\nDecrypt:%s\n", input_data);
	return 0;
}
