





#include "common.h"

#define MODULUS_SIZE 2048
#define EXPONENT RSA_F4
#define CALLBACK_FN NULL
#define CALLBACK_ARG NULL
#define SHA1_LEN 20

char input_data[128] = "Hello Iam going to be the data which will be hashed";


void initOpenSSL(void)
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	SSL_library_init();
}





EC_KEY*  generate_KeyPair(void)
{
	EC_KEY *eckey;

	eckey = EC_KEY_new_by_curve_name(NID_secp256k1);

	if (!eckey) {
		printf("Error in ec key\n");
		abort();
	}

	if (!EC_KEY_generate_key(eckey)) {
		printf("Error:%ld\n", ERR_get_error());
		return NULL;
	}
	return eckey;
}

char * generate_MessageDigest(void)
{
	SHA_CTX hash_ctx;
	char *hash_res = (char *)malloc(20);

	if (!hash_res)
		return NULL;

	SHA1_Init(&hash_ctx);
	SHA1_Update(&hash_ctx, input_data, strlen(input_data));	
        SHA1_Final(hash_res, &hash_ctx);
	return hash_res;	
}

int main(int argc, char *argv[])
{

	EC_KEY *eckey1, *eckey2;
	char *message_digest;
	char signature[1024];
	int siglen, i=0;

	initOpenSSL();

	eckey1 = generate_KeyPair();
	eckey2 = generate_KeyPair();

	message_digest = generate_MessageDigest();


	/*
	 *	Syntax: int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen,
	 *			      unsigned char *sig, unsigned int *siglen, 
	 *			      EC_KEY *eckey);
	 *
	 */

	if (ECDSA_sign(NID_sha1, message_digest, SHA1_LEN, 
				signature, &siglen, eckey2) == 1)
		printf("ECKey Sign successful with length:%d\n", siglen);
	else {
		printf("Error\n");
		exit(1);
	}
	printf("Signature:\n");
	for (i = 0; i < 2*siglen; i++)
	{
		if (i%2 == 0)
			printf("%x", (signature[i/2]>>4)&0xf);
		else
			printf("%x", (signature[i/2])&0x0f);
	}
	printf("\n");
	
	/*
	 *	Syntax: int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen,
	 *				unsigned char *sig, unsigned int siglen, EC_KEY *eckey);
	 *
	 */

	if (ECDSA_verify(NID_sha1, message_digest, SHA1_LEN,
				signature, siglen, eckey2) == 1)
		printf("Signature Verified with eckey2\n");
	else {
		printf("Error in verification with eckey2\n");
	}
	
	if (ECDSA_verify(NID_sha1, message_digest, SHA1_LEN,
				signature, siglen, eckey1) == 1)
		printf("Signature Verified with eckey1\n");
	else {
		printf("Error in verification with eckey1\n");
	}

	return 0;
}
