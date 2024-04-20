// TCP_Sender.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h> // For TCP_CONGESTION
#include <arpa/inet.h>
#include <time.h>

#define BUFFER_SIZE 1024

/*    struct sockaddr_in {
           sa_family_t     sin_family;     AF_INET 
           in_port_t       sin_port;       Port number 
           struct in_addr  sin_addr;      IPv4 address 
       };
*/


void set_congestion_control(int sockfd, const char *algo) {
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_CONGESTION, algo, strlen(algo)) != 0) {
        perror("setsockopt TCP_CONGESTION failed");
        exit(EXIT_FAILURE);
    }
}

void gen_and_write(char buffer[1024], int sockfd)
{
    const int fileSize = 2097152; 
    // send first the size of the file
    if (send(sockfd, &fileSize, sizeof(fileSize), 0) == -1) {
        perror("ERROR writing to socket");
        exit(1);
    }

    // Generate and send a file of at least 2MB
    for (int i = 0; i < fileSize / BUFFER_SIZE; i++)
    {
        memset(buffer, 'A', BUFFER_SIZE);
        long n = write(sockfd, buffer, BUFFER_SIZE);
        if (n < 0)
        {
            perror("ERROR writing to socket");
            exit(1);
        }
    }
}
int main(int argc, char *argv[]) {
    int sockfd, portno = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024];
    char *ip = NULL;
    char congestion_control_algo[256] = "reno"; // Default to "reno"

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-ip") == 0 && i + 1 < argc) {
            ip = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            portno = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-algo") == 0 && i + 1 < argc) {
            strncpy(congestion_control_algo, argv[++i], sizeof(congestion_control_algo) - 1);
        }
    }

    if (ip == NULL || portno == 0) {
        fprintf(stderr, "Usage: %s -ip IP -p PORT -algo ALGO\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(EXIT_FAILURE);
    }

    set_congestion_control(sockfd, congestion_control_algo);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) { //checks whaever the ip format is okay na dconverts it to binary
        fprintf(stderr, "Invalid IP address format\n");
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { //connect the sender and the receiver 
        perror("ERROR connecting");
        exit(EXIT_FAILURE);
    }

    //gen_and_write(buffer, sockfd);

    do {
        gen_and_write(buffer, sockfd); // Step 3: Send the file

        printf("File sent. Send again? (yes/no): ");
        scanf("%s", buffer);

        long n = write(sockfd, buffer, BUFFER_SIZE);
        if (n < 0)
        {
            perror("ERROR writing to socket");
            exit(1);
        }
    } while (strcmp(buffer, "no") != 0); // Step 4: User decision loop

    // Step 5: Properly close the socket and clean up
    close(sockfd);
    printf("Connection closed. Exiting.\n");

    return 0;
}
