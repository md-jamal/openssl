
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
	/*
	 *	In OpenSSL fields are internally identified through an integer
	 *	value known as the NID.Add the data based on NID
	 */
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (!ex)
		return 0;
	sk_X509_EXTENSION_push(sk, ex);
	
	return 1;	
}

/*
 *	In order to create a certificate request:we have to create an X509_REQ object,
 *	add a subject name and public key to it, add all the desired extensions, and
 *	sign the request with the private key.
 */


X509_REQ * generate_Certificate(EVP_PKEY *pkey)
{
	
	/*
	 *	An X.509 certificate request is represented by an X509_REQ object 
	 *	in OpenSSL.A certificate request's main component is the public
	 *	half of the key pair. It also contains a subject Name field and
	 *	additional X.509 attributes. In reality, the attributes are
	 *	optional parameters for the request, but the subject name
	 *	should always be present.
	 */
	X509_REQ *req;
	/*
	 *	The object type X509_NAME represents a certificate name.Specifically,
	 *	a certificate request has only a subject name, while full certificates
	 *	contain a subject name and an issuer name.
	 */
	X509_NAME *name = NULL;
	STACK_OF(X509_EXTENSION) *ext = NULL;

	/*
	 *  Get a new X509_REQ structure
	 */
	if ((req = X509_REQ_new()) == NULL)
		goto err;

	/*
	 *	Add the public key portion of the private key to the request.
	 */
	X509_REQ_set_pubkey(req, pkey);

	name = X509_REQ_get_subject_name(req);

	/*
	 *	int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type,
	 *					const unsigned char *bytes, int len, int loc,
	 *					int set);
	 *
	 *	 Its add a field whose name is identified by a string field .The field value
	 *	 to be added is in bytes of length len.If len = -1 , it internally calculates
	 *	 the length using strlen.The type of the field is defined by type which can be
	 *	 either be a definition of the type of "bytes"(such as MBSTRING_ASC)
	 */

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

	FILE *fp2 = fopen("cert.pem", "w");

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

	/*It writes the x509 into PEM format in the file pointer specified
	 * specified by the first argument
	 */
	PEM_write_X509_REQ(fp2, x509);

	/*Free the allocated EVP_PKEY structure*/
	EVP_PKEY_free(root_pkey);

	X509_REQ_free(x509);

	return 0;
}
