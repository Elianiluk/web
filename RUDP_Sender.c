#include "RUDP_API.h"
#include <fcntl.h> // For file operations
#include <errno.h>

// Function prototypes
void usage(char *progname);

int main(int argc, char *argv[]) {
    if (argc != 6 || strcmp(argv[1],"-ip") != 0 || strcmp(argv[3],"-p") != 0 ) {
        usage(argv[0]);
        return FAILURE;
    }

    const char *ip = argv[2];
    int port = atoi(argv[4]);
    const char *filename = argv[5];   

    // Create the RUDP socket
    int sockfd = rudp_socket(AF_INET, SOCK_DGRAM, 0, 1);
    if (sockfd < 0) {
        printf("Failed to create RUDP socket\n");
        return FAILURE;
    }

    // Set up the destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &dest_addr.sin_addr) <= 0) {
        printf("Invalid IP address format\n");
        return FAILURE;
    }     

    // Buffer for reading from the file
    char buffer[4194304]; // 4 MB 
    ssize_t read_bytes, sent_bytes;

    // handshake with the receiver (send SYN)
    char buf[1];
    int attempts = 0;    
    while (attempts < MAX_RETRANS_ATTEMPTS) {    
        sent_bytes = rudp_send(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr), buf, 1, SYN); 
        if (sent_bytes < 0) {
            attempts++;
        } else {
            break;
        }
    }
    if (sent_bytes < 0) {
        printf("Failed to handshake with the receiver\n");
        return FAILURE;
    }
    
    printf("Sending the file\n");
    int keepSending = 0;
    // Send the file in chunks
    do {        
        // Open the file
        int file_fd = open(filename, O_RDONLY);
        if (file_fd < 0) {
            printf("Failed to open file");
            return FAILURE;
        }

        read_bytes = read(file_fd, buffer, sizeof(buffer));
        // close the file so that it can be reopen in the next loop iteration.
        close(file_fd);
        
        if (read_bytes > 0) {
            sent_bytes = rudp_send(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr), buffer, read_bytes, 0);
            
            if (sent_bytes < 0) {
                printf("Failed to send data\n");
                break;
            }
        }

        printf("Do you want to send the file again? (1 - yes, any other character - no): ");
        scanf("%d", &keepSending);        
    } while (keepSending == 1);

    // send FIN to indicate the receiver to stop listening.
    sent_bytes = rudp_send(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr), buf, 1, FIN);        

    // Close RUDP connection    
    printf("Closing the connection\n");
    rudp_close(sockfd);
    printf("Connection closed\n");

    return 0;
}

void usage(char *progname) {
    printf("Usage: %s -ip <IP> -p <Port> <Filename>\n", progname);
    printf("Example: %s -ip 127.0.0.1 -p 12345 myfile.txt\n", progname);
}

