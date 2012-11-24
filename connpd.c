#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
//#include <sys/resource.h>

#define MAINTAIN_FDS -1

void cleanup_connpd_ptr(int); //Exit the connpd pointer gracefully

int main(void)
{
    int pid;
    int fd;

    if (geteuid() != 0) {
        printf("Must run as root!\n");
        return 0;
    }

    pid = fork();
    if (pid < 0) {
        printf("No process to fork!\n");
        return 0;
    }

    if (!pid){
        setsid();
        chdir("/");
        umask(0);
        for (fd = 0; fd < 3; fd++) //Close std io. 
            close(fd);
        signal(SIGTERM, cleanup_connpd_ptr);
        //setpriority(PRIO_PROCESS, 0, PRIO_MIN); //higher priority.
        while (!close(MAINTAIN_FDS)); //Maintain the fds of connp.
    }

    exit(0);
}

void cleanup_connpd_ptr(int a)
{
    exit(0);
}
