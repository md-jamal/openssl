





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





DSA*  generate_KeyPair(void)
{
	DSA *dsa;

	dsa = DSA_generate_parameters(1024, NULL, 0, NULL, NULL, NULL, NULL);
	DSA_generate_key(dsa);
	return dsa;
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

	DSA *dsa1, *dsa2;
	char *message_digest;
	char *signature ;
	int siglen, i=0;

	initOpenSSL();

	dsa1 = generate_KeyPair();
	dsa2 = generate_KeyPair();

	signature = (char *)malloc(DSA_size(dsa1));

	message_digest = generate_MessageDigest();


	/*
	 *	Syntax: int DSA_sign(int type, const unsigned char *dgst, int dgstlen,
	 *			      unsigned char *sig, unsigned int *siglen, 
	 *			      DSA *dsa);
	 *
	 */

	if (DSA_sign(NID_sha1, message_digest, SHA1_LEN, 
				signature, &siglen, dsa1) == 1)
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
	 *	Syntax: int DSA_verify(int type, const unsigned char *dgst, int dgstlen,
	 *				unsigned char *sig, unsigned int siglen, DSA *dsa);
	 *
	 */

	if (DSA_verify(NID_sha1, message_digest, SHA1_LEN,
				signature, siglen, dsa2) == 1)
		printf("Signature Verified with dsa2\n");
	else {
		printf("Error in verification with dsa2\n");
	}
	
	if (DSA_verify(NID_sha1, message_digest, SHA1_LEN,
				signature, siglen, dsa1) == 1)
		printf("Signature Verified with dsa1\n");
	else {
		printf("Error in verification with dsa1\n");
	}

	DSAparams_print_fp(stdout, dsa1);


	return 0;
}
