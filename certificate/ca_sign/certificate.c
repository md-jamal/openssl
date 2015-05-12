
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

int add_ext_to_cert(X509 *cert, X509 *root, int nid, char *value)
{
	X509_EXTENSION *ex;  
	X509V3_CTX ctx;  

	X509V3_set_ctx(&ctx,root, cert, NULL, NULL, 0);  
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);  
	if (!ex)  
		return 0;  

	X509_add_ext(cert,ex,-1);  
	X509_EXTENSION_free(ex);  

	return 1;
}


X509* sign_request_by_ca(X509 *root_x509, X509_REQ *req, EVP_PKEY *pkey, int ca)
{
	X509 *x509;
	STACK_OF(X509_EXTENSION) *exts;
	X509_EXTENSION *ex;
	X509_NAME *name;
	EVP_PKEY *key;
	int len;
	unsigned char sha_hash[SHA_DIGEST_LENGTH];
	unsigned char name_hash[SHA_DIGEST_LENGTH];
	unsigned char pubkey_hash[SHA_DIGEST_LENGTH] = {0};

	key = X509_REQ_get_pubkey(req);
	if (!key) {
		fprintf(stderr, "Cannot get public key from request\n");
		return NULL;
	}

	x509 = X509_new();
	X509_set_version(x509, 2L);
	X509_set_issuer_name(x509, X509_get_subject_name(root_x509));
	name = X509_REQ_get_subject_name(req);
	X509_set_subject_name(x509, name);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), (long)365*24*60*60);
	X509_set_pubkey(x509, key);
	EVP_PKEY_free(key);

	// Set serial number
	if (X509_NAME_digest(name, EVP_sha1(), name_hash, &len) == 1) {
		if (X509_pubkey_digest(x509, EVP_sha1(), pubkey_hash, &len)) {
			int i;
			for (i = 0; i < SHA_DIGEST_LENGTH; i++)
				sha_hash[i] = name_hash[i] ^ pubkey_hash[i];
			ASN1_INTEGER *serial_num = ASN1_INTEGER_new();
			if (serial_num) {
				ASN1_OCTET_STRING_set(serial_num, sha_hash, SHA_DIGEST_LENGTH);
				X509_set_serialNumber(x509, serial_num);
			} else {
				ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
			}
		} else {
			ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
		}
	} else {
		ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	}

	if (ca) {
		add_ext_to_cert(x509,x509,NID_basic_constraints, "CA:TRUE");  
		add_ext_to_cert(x509,root_x509, NID_authority_key_identifier, "keyid:always,issuer:always");  
	} else { 
		add_ext_to_cert(x509,x509,NID_basic_constraints, "critical,CA:FALSE,pathlen:1");  
	}
	add_ext_to_cert(x509,x509,NID_subject_key_identifier, "hash");  

	X509V3_EXT_cleanup();
	X509_sign(x509, pkey, EVP_sha1());

	return x509;
}



X509 * generate_RootCertificate(EVP_PKEY *pkey)
{
	
	X509 *x509;
	X509_NAME *name;
	STACK_OF(X509_EXTENSION) *ext = NULL;
	X509_EXTENSION *ex;

	int len;
	unsigned char name_hash[SHA_DIGEST_LENGTH];
	unsigned char pubkey_hash[SHA_DIGEST_LENGTH];
	unsigned char sha_hash[SHA_DIGEST_LENGTH];

	if ((x509 = X509_new()) == NULL)
		goto err;

	X509_set_pubkey(x509, pkey);

	X509_set_version(x509, 2L);

	/*validation time
	 */
	X509_gmtime_adj(X509_get_notBefore(x509), 0); //current time
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // a year:365*24*60*60 sec

	
	/*
	 *Since this is a self-signed certificate, we set the name of the issuer to the 
	 * name of the subject
	 */
	name = X509_get_subject_name(x509);

	X509_NAME_add_entry_by_NID(name, NID_countryName, MBSTRING_ASC, (unsigned char *)"IN",
					-1, -1, 0);

	X509_NAME_add_entry_by_NID(name, NID_organizationName, MBSTRING_ASC, (unsigned char *)"Embedded",
					-1, -1, 0);

	X509_NAME_add_entry_by_NID(name, NID_organizationalUnitName, MBSTRING_ASC, (unsigned char *)"CDAC",
					-1, -1, 0);

	X509_NAME_add_entry_by_NID(name, NID_stateOrProvinceName, MBSTRING_ASC, (unsigned char *)"Telangana",
					-1, -1, 0);

	X509_NAME_add_entry_by_NID(name, NID_localityName, MBSTRING_ASC, (unsigned char *)"Hyderabad",
					-1, -1, 0);

	X509_NAME_add_entry_by_NID(name, NID_pkcs9_emailAddress, MBSTRING_ASC, (unsigned char *)"mjmohiuddin@cdac.in",
					-1, -1, 0);

	X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char *)"CDAC Root CA",
					-1, -1, 0);

	/*
	 *	Set the issuer name
	 */

	X509_set_issuer_name(x509, name);

	/*
	 *	Set serial number:A unique identifier assigned by CA which issued the
	 *	certificate.It is unique within the CA.
	 */

	if (X509_NAME_digest(name, EVP_sha1(), name_hash, &len) == 1) {
		if (X509_pubkey_digest(x509, EVP_sha1(), pubkey_hash, &len)) {
			ASN1_INTEGER *serial_num =ASN1_INTEGER_new();
			int i;
			for (i = 0; i < SHA_DIGEST_LENGTH; i++)
				sha_hash[i] = name_hash[i] ^ pubkey_hash[i];
			if (serial_num) {
				ASN1_OCTET_STRING_set(serial_num, sha_hash, SHA_DIGEST_LENGTH);
				X509_set_serialNumber(x509, serial_num);
			}else {
				ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
			}
		}else {
			ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
		}
	}else {
		ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	}

	/*
	 *	Set basic constraints
	 */

	BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
	if (bc) {
		bc -> ca = 1;
		X509_add1_ext_i2d(x509, NID_basic_constraints, bc, 0, X509V3_ADD_DEFAULT);
		BASIC_CONSTRAINTS_free(bc);
	}else {
		fprintf(stderr, "Cannot create Basic Constraints");
	}

	// Set subject key identifier
	ASN1_OCTET_STRING *subjectKeyIdentifier = ASN1_OCTET_STRING_new();
	if (subjectKeyIdentifier) {
		if (!pubkey_hash[0]) {
			X509_pubkey_digest(x509, EVP_sha1(), pubkey_hash, &len);
		}
		ASN1_OCTET_STRING_set(subjectKeyIdentifier, pubkey_hash, SHA_DIGEST_LENGTH);
		X509_add1_ext_i2d(x509, NID_subject_key_identifier, subjectKeyIdentifier, 0, X509V3_ADD_DEFAULT);
		ASN1_OCTET_STRING_free(subjectKeyIdentifier);
	}

	// Set authority keyid
	AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
	if (akid) {
		akid->issuer = GENERAL_NAMES_new();
		GENERAL_NAME *gen_name = GENERAL_NAME_new();
		gen_name->type = GEN_DIRNAME;
		gen_name->d.directoryName = X509_NAME_dup(X509_get_subject_name(x509));
		sk_GENERAL_NAME_push(akid->issuer, gen_name);
		akid->keyid = (ASN1_OCTET_STRING*)X509_get_ext_d2i(x509, NID_subject_key_identifier, NULL, NULL);
		akid->serial = ASN1_INTEGER_dup(X509_get_serialNumber(x509));

		X509_add1_ext_i2d(x509, NID_authority_key_identifier, akid, 0, X509V3_ADD_DEFAULT);

		AUTHORITY_KEYID_free(akid);
	}

	if (!X509_sign(x509, pkey, EVP_sha1()))
		goto err;

	return x509;

err:
	return NULL;

}


int main(int argc, char *argv[])
{

	FILE *fp = fopen("ecdsa.pem", "w");

	FILE *fp1 = fopen("ecdsa_pub.pem", "w");

	FILE *fp2 = fopen("root.pem", "w");
	
	FILE *fp3 = fopen("cert.pem", "r");

	FILE *fp4 = fopen("cert_sign.pem", "w");

	X509 *x509, *user;
	
	X509_REQ *req;

	/*EVP_PKEY is a structure used by openssl to store private keys*/
	EVP_PKEY *root_pkey;

	initOpenSSL();

	/*Generate a private key for root CA*/
	root_pkey = generate_PrivateKey();

	/*Printing it on the stdout*/
	//PEM_write_PrivateKey(stdout, root_pkey, NULL, NULL, 0, 0, NULL);

	//PEM_write_PUBKEY(stdout, root_pkey);

	/*Copying private key on the file */
	PEM_write_PrivateKey(fp, root_pkey, NULL, NULL, 0, 0, NULL);

	/*Copying public key on the file */
	PEM_write_PUBKEY(fp1, root_pkey);

	/*Generate Certificate*/
	x509 = generate_RootCertificate(root_pkey);

	//X509_print_fp(stdout, x509);

	PEM_write_X509(fp2, x509);


	req = PEM_read_X509_REQ(fp3, NULL, 0, NULL);

	user = sign_request_by_ca(x509, req, root_pkey, 0);

	PEM_write_X509(fp4, user);

	/*Free the allocated EVP_PKEY structure*/
	EVP_PKEY_free(root_pkey);

	X509_free(x509);

	X509_free(user);

	fclose(fp1);
	
	fclose(fp2);

	fclose(fp3);

	fclose(fp4);

	return 0;
}
