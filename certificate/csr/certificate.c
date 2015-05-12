
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

int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value)
{
	
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (!ex)
		return 0;
	sk_X509_EXTENSION_push(sk, ex);
	
	return 1;	
}


X509_REQ * generate_Certificate(EVP_PKEY *pkey)
{
	
	X509_REQ *req;
	X509_NAME *name = NULL;
	STACK_OF(X509_EXTENSION) *ext = NULL;

	if ((req = X509_REQ_new()) == NULL)
		goto err;


	X509_REQ_set_pubkey(req, pkey);

	name = X509_REQ_get_subject_name(req);

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "IN", -1, -1, 0);

	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, "CDAC", -1, -1, 0);

	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, "Telangana", -1, -1, 0);

	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, "Hyderabad", -1, -1, 0);


	#ifdef EXTENSIONS_ENABLED
	
	exts = sk_X509_EXTENSION_new_null();

	add_ext(exts, NID_key_usage, "critical,digitalSignature,keyEncipherment");

	add_ext(exts, NID_subject_alt_name, "email:mjmohiuddin@cdac.in");

	X509_REQ_add_extensions(req, exts);

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	
	#endif

	if (!X509_REQ_sign(req, pkey, EVP_sha1()))
		goto err;

	return req;

err:
	return NULL;

}


int main(int argc, char *argv[])
{

	FILE *fp = fopen("ecdsa.pem", "w");

	FILE *fp1 = fopen("ecdsa_pub.pem", "w");

	X509_REQ *x509;

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

	/*Generate Certificate*/
	x509 = generate_Certificate(root_pkey);

	X509_REQ_print_fp(stdout, x509);

	/*Free the allocated EVP_PKEY structure*/
	EVP_PKEY_free(root_pkey);

	X509_REQ_free(x509);

	return 0;
}
