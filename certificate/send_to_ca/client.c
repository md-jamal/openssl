#include "common.h"



int main(int argc, char *argv[])
{
	int sockfd;
	FILE *fp;
	struct sockaddr_in server_address;

	if (argc != 2) {
		printf("Help: <exe> <IP Address>\n");
		exit(1);
	}

	fp = fopen("cert.csr", "rb");
	if (fp == NULL) {
		perror("File Opening\n");
		return 1;
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0))<0) {
		printf("Could not create socket\n");
		return 1;
	}

	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(8484);
	server_address.sin_addr.s_addr = inet_addr(argv[1]);

	if (connect(sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
		perror("Error : Connection Failed\n");
		return 1;
	}

	for (;;) {
		unsigned char buff[256]= {0};
		int bytes_read = fread(buff, 1, 256, fp);
		
		printf("Bytes read:%d\n", bytes_read);
		if (bytes_read > 0) {
			printf("sending\n");
			write(sockfd, buff, bytes_read);
		}	
		if (bytes_read < 256) {
			if (feof(fp))
				printf("End of file\n");
			if (ferror(fp))
				printf("Error Reading\n");
			break;
		}
	}
	close(sockfd);
	return 0;
}
