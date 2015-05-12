
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

int main(int argc, char *argv[])
{

	SHA_CTX hash_ctx;

	char input_data[128];

	/*SHA-1 returns a 160 bit hash value*/
	unsigned char hash_ret[20];

	int i;

	while (1){
		printf("\nEnter data to be hashed\n");

		scanf("%s", input_data);
		
		/*Initializes the SHA1_CTX structure*/
		SHA1_Init(&hash_ctx);

		/*We can repeatedly call Update func with chunks of data*/
		SHA1_Update(&hash_ctx, input_data, strlen(input_data));

		/*Places the message digest in first arg,and erases the SHA1_CTX*/
		SHA1_Final(hash_ret, &hash_ctx);

		printf("\nInput String:%s\n",input_data);

		printf("\n Hash Value:");

		for (i = 0; i < 40; i++) {
			if (i%2 == 0)
				printf("%x",(hash_ret[i/2]>>4)&0xf);
			else
				printf("%x",(hash_ret[i/2])&0xf);
		}
	}


	return 0;
}
