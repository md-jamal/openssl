/* Server Program*/

#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<stdlib.h>//for exit
#include <string.h>//for memset

int main(int argc,char *argv[])
{
	int simplesocket=0;
	int simpleport=0;	
	int returnstatus=0;
	struct sockaddr_in SimpleServer;//this structure purpose is to provide a standard way of handling endpoint addresses for network communications

	/*Step1: Create a socket*/

	simplesocket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);//socket() is used to create a network endpoint,and it returns a socket descriptor that will be used by the later functions

	/*int socket(int domain, int type, int protocol);

	AF_INET-->IPV4 Internet Protocols
	SOCK_STREAM-> communications are connection-based , sequenced ,reliable and two-way
	IPPROTO_TCP-->Protocol*/

	if(simplesocket==-1)
	{
		fprintf(stderr,"could not create a socket");
		exit(1);
	}
	else
	{
		fprintf(stderr,"socket created\n");
	}

	/*Step2: set up the address structure*/

	memset(&SimpleServer,'0',sizeof(struct sockaddr_in));
	SimpleServer.sin_family=AF_INET;
	SimpleServer.sin_addr.s_addr=inet_addr("10.244.10.220");//INADDR_ANY indicates we are binding it to all of our local hosts address
	SimpleServer.sin_port=htons(9104);

	bind(simplesocket,(struct sockaddr *)&SimpleServer,sizeof(SimpleServer));//we are binding the socket to the address and port

	/*step3:Queue to accept connections*/

	
	listen(simplesocket,5);
		

	/*step4: Get ready to accept connections*/

	struct sockaddr_in ClientName={0};
	int ChildSocket;
	int ChildLength=sizeof(ClientName);	
	ChildSocket=accept(simplesocket,(struct sockaddr *)&ClientName,&ChildLength);
	while(1)
	{

		
		char buffer[25]="TEMP";	
		int temperature;
		

		if(ChildSocket==-1)
		{
			fprintf(stderr,"error accepting the connection");
			exit(1);
		}
		
		write(ChildSocket,buffer,sizeof(buffer));
		read(ChildSocket,&temperature,sizeof(temperature));
		printf("Temperature:%d\n",temperature);
		sleep(5);
	}
	close(ChildSocket);
	close(simplesocket);
	return 0;
}	
