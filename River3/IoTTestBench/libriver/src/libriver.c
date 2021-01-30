#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#define PORT 8080

int connect_to_server()
{
    int server_sock;
    struct sockaddr_in server_addr;

    if ((server_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(PORT);

    if (connect(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("Connection failed! %s\n", strerror(errno));
        return -1;
    }

    return server_sock;
}

void read_program_name(char* program_name)
{
    FILE* fp = fopen("/proc/self/cmdline", "r");
    fscanf(fp, "%s\n", program_name);
    fclose(fp);
}

extern char *program_invocation_name;
extern char *program_invocation_short_name;

/**
 * We will redirect stdout to our server socket at library load time
 * For this to work, the process needs to we linked with the current library (-lriver)
 * and started with LD_PRELOAD=path/to/libriver.so
 */
void __attribute__ ((constructor)) my_init(void)
{
    int server_sock = 0;

    server_sock = connect_to_server();

    char* path = getenv("_");
    printf("PATH has val %s\n", path);

    char program_name[256];
    read_program_name(program_name);
    printf("==\n%s\n==\n", program_name);

    printf("%s\n", program_invocation_name);
    printf("%s\n", program_invocation_short_name);

    dup2(server_sock, STDOUT_FILENO); /* Redirect stdout to socket pipe */
}

void __attribute__ ((destructor)) my_fini(void)
{
}
