
/*
 *gcc test.c -lcrypto -lssl
 */

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"

#include <stdio.h>

BIO *bio;

int main(int argc, char *argv[])
{
	int x;
	char buf[80];
	int value = 23;
	
	//This is used to create a new BIO object with the specified hostname and port
	bio = BIO_new_connect("10.244.10.220:9104");
	if (bio == NULL) {
		printf("Connection failed\n");
		abort();
	}else {
		printf("Connection successful\n");
	}
	//The call to BIO_do_connect checks to see if the connection was successful or not
	if (BIO_do_connect(bio) <= 0)
	{
		printf("Handle Failed Connection\n");
		abort();
	}

	//Reading or writing to a BIO object,will always be performed using two functions:BIO_read and BIO_write.
	//BIO_read will attempt to read a certain number of bytes from the server. It returns the number of bytes read,or 0 or -1.
	
	x = BIO_read(bio, buf, sizeof(buf));
	if (x == 0) {
		printf("connection closed\n");
	}else if (x < 0) {
		if (!BIO_should_retry(bio))
		{
			printf("Handle failed read\n");
		}
	}
	printf("read:%s\n", buf);

	//BIO_Write will attempt to write bytes to the socket.It returns the number of bytes actually written, or 0 or -1.

	if (BIO_write(bio, &value, sizeof(int)) <= 0)
	{
		if (! BIO_should_retry(bio))
		{
			printf("Handle failed write\n");
		}
	}


	//closing the connection can be done in two fashions:BIO_reset,or BIO_free_all.If you are going to reuse the object, use the first.If you won't be reusing it , use the second
	
	BIO_free_all(bio);

	return 0; 
}
