
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

int main(int argc, char *argv[])
{

	MD5_CTX hash_ctx;

	char input_data[128];

	/*MD5 returns a 128 bit hash value*/
	unsigned char hash_ret[16];

	int i;

	while (1){
		printf("\nEnter data to be hashed\n");

		scanf("%s", input_data);
		
		/*Initializes the MD5_CTX structure*/
		MD5_Init(&hash_ctx);

		/*We can repeatedly call Update func with chunks of data*/
		MD5_Update(&hash_ctx, input_data, strlen(input_data));

		/*Places the message digest in first arg,and erases the MD5_CTX*/
		MD5_Final(hash_ret, &hash_ctx);

		printf("\nInput String:%s\n",input_data);

		printf("\n Hash Value:");

		for (i = 0; i < 32; i++) {
			if (i%2 == 0)
				printf("%x",(hash_ret[i/2]>>4)&0xf);
			else
				printf("%x",(hash_ret[i/2])&0xf);
		}
	}


	return 0;
}
