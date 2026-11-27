#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
int main(int argc,char **argv){
    if(argc<3||strcmp(argv[1],"/usr/bin/sandbox-exec")!=0)return 64;
    /* Foundation Process may already make the child a process-group leader.
       A group leader cannot setsid(), although a direct CLI child can. Move
       only this child into its parent's group, then create our own session.
       If posix_spawn already created a session, verify and retain it. */
    if(getsid(0)!=getpid()){
        if(getpgrp()==getpid()){
            pid_t parent_group=getpgid(getppid());
            if(parent_group<=0||parent_group==getpid()||setpgid(0,parent_group)<0){perror("session group preparation");return 77;}
        }
        if(setsid()<0){perror("session boundary");return 77;}
    }
    if(getsid(0)!=getpid()||getpgrp()!=getpid()){fputs("session ownership unverified\n",stderr);return 77;}
    execv(argv[1],&argv[1]);perror("sandbox launch");return 78;
}
