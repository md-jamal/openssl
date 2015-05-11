





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

	RSA *rsa1, *rsa2;
	char *message_digest;
	char signature[1024];
	int siglen, i=0;

	initOpenSSL();

	rsa1 = generate_KeyPair();
	rsa2 = generate_KeyPair();

	message_digest = generate_MessageDigest();


	/*
	 *	Syntax: int RSA_sign(int type, const unsigned char *m, unsigned int m_len,
	 *			      unsigned char *sigret, unsigned int *siglen, RSA *rsa);
	 *
	 *	RSA_sign() signs the message digest m of size m_len using the private key rsa
	 *	as specified in PKCS #1 v2.0. It stores the signature in sigret and the signature
	 *	size is siglen.sigret must point to RSA_size(rsa) bytes of memory.
	 *
	 *	type denotes the message digest algorithm used to generate m.
	 *
	 */

	if (RSA_sign(NID_sha1, message_digest, SHA1_LEN, 
				signature, &siglen, rsa1) == 1)
		printf("RSA Sign successful with length:%d\n", siglen);
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
	 *	Syntax: int RSA_verify(int type, const unsigned char *m, unsigned int m_len,
	 *				unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
	 *
	 *	RSA_verify() verifies that the signature sigbuf of size siglen matches a given
	 *	message digest m of size m_len. type denotes the message digest algorithm that
	 *	was used to generate the signature. rsa is the signer's public key.
	 *
	 *	Returns 1 on successful verification , 0 otherwise
	 */

	if (RSA_verify(NID_sha1, message_digest, SHA1_LEN,
				signature, siglen, rsa2) == 1)
		printf("Signature Verified with rsa2\n");
	else {
		printf("Error in verification with rsa2\n");
	}
	
	if (RSA_verify(NID_sha1, message_digest, SHA1_LEN,
				signature, siglen, rsa1) == 1)
		printf("Signature Verified with rsa1\n");
	else {
		printf("Error in verification with rsa1\n");
	}

	return 0;
}
