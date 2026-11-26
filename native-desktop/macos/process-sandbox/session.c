#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(int argc,char **argv){
    if(argc<3||strcmp(argv[1],"/usr/bin/sandbox-exec")!=0)return 64;
    if(setsid()<0){perror("session boundary");return 77;}
    execv(argv[1],&argv[1]);perror("sandbox launch");return 78;
}
