#include "common.h"
#include "pthread.h"



void *server_thread(void *arg)
{
	int fd = *(int *)arg;
	FILE *fp;
	unsigned char buff[256]= {0};
	int bytesReceived;

	pthread_detach(pthread_self());
	
        fp = fopen("cert.csr", "ab");
	if (fp == NULL) {
		perror("File Opening Error\n");
		pthread_exit(NULL);
	}
	
	memset(buff, 0, sizeof(buff));

	while((bytesReceived = read(fd, buff, 256)) > 0) {
		printf("Bytes received:%d\n", bytesReceived);
		fwrite(buff, 1, bytesReceived, fp);	
	}

	if(bytesReceived < 0) {
		printf("Read Error\n");
		pthread_exit(NULL);
	}
	fclose(fp);
	free(arg);
	system("openssl req -in cert.csr -text -noout");
	pthread_exit(NULL);
}





int main(int argc, char *argv[])
{

	int fd, clientfd, ret;
	struct sockaddr_in server_addr, client;
	size_t size = sizeof(client);
	int *sockid;
	pthread_t tid;

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8484);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("Error in Creating Socket\n");
		return 1;
	}
		
	if ((bind (fd, (struct sockaddr *)&server_addr, sizeof(server_addr))) < 0) {
		perror("Error in binding socket\n");
		return 1;
	}

	if ((listen(fd , 10)) == -1) {
		perror("Failed in listen\n");
		return 1;
	}
	while(1) {
		clientfd = accept(fd, (struct sockaddr *)&client, &size);
		sockid = (int *)malloc(sizeof(int));
		*sockid = clientfd;
		ret = pthread_create(&tid, NULL, server_thread, (void *)sockid);
		if (ret != 0) {
			perror("Unable to create thread\n");
			break;
		}
	}

	return 0;

}
