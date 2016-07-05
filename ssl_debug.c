#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "ssl_debug.h"
#include "api_test.h"


int menu();

int main(int argc,char *argv[])
{
    int mode = -1;
    mode = menu();
    system("clear");
    if(mode == 1){
            printf("run as server.\n");
            ssl_server_libssl();
    }
    else if(mode == 2){
            printf("run as client.\n");
            ssl_client_libssl() ;
    }
    else if(mode == 3){
        printf("SM2 Key Test\n");
        test_sm2_evp(2);

    }
    else if (mode == 0){
        return 0;
    }
    else {
        printf("Unknow Operation\n");
    }

	return 0;
}




int menu()
{
    char c;
    int n;
    printf("#################################\n");
    printf("\t GmSSL Test App v0.1\n");
    printf("\t 1. Server Test \n");
    printf("\t 2. Client  Test  \n");
    printf("\t 3. SM2 Key Test \n");
    printf("\t 4. SM2 Cert Test \n");
    printf("\n");
    printf("\t 0. Quit  \n");
    printf("#################################\n");
    do{
        c = getchar();
        n = c-48;
    }while(n<0 || n >9);
    return n;
}
