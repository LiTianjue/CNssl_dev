#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "ssl_debug.h"


int main(int argc,char *argv[])
{
	if(argc == 1)
        ssl_server_libssl();

	if(argc == 2)
	{
		if(strstr(argv[1],"client")){
			printf("run as client.\n");
			ssl_client_libssl();
		}else if(strstr(argv[1],"server")){
			printf("run as server.\n");
			ssl_server_libssl();
		}
	}
	else
	{
    //	printf("unknow mode .\n");
	}

	return 0;
}
