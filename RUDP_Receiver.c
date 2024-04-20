#include "RUDP_API.h"
#include <time.h>

// Function prototypes
void usage(char *progname);

int main(int argc, char *argv[]) {    
    if (argc != 3 || strcmp(argv[1], "-p") != 0) {  
        usage(argv[0]);
        return FAILURE;
    }

    printf("~~~~~~~~ RUDP Receiver ~~~~~~~~\n");
    int port = atoi(argv[2]);    
    if (port <= 0) {
        printf("Invalid port number\n");
        return FAILURE;
    }

    // Create the RUDP socket
    int sockfd = rudp_socket(AF_INET, SOCK_DGRAM, 0, 0);
    if (sockfd < 0) {
        printf("Failed to create RUDP socket.\n");
        return FAILURE;
    }
    printf("Socket created.\n");

    // Bind the socket to the provided port
    struct sockaddr_in my_addr;
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    my_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0) {
        printf("Bind failed");
        close(sockfd);
        return FAILURE;
    }

    printf("Connection established.\n");
    printf("Listening on port %d...\n", port);

    FILE* file = fopen("stats", "w+");
    if (file == NULL) {
        printf("Error opening  stats file!\n");
        return 1;
    }
    fprintf(file, "\n\n~~~~~~~~ Statistics ~~~~~~~~\n");
    double average_time = 0;
    double average_speed = 0;
    clock_t start, end;

    char totalData[4194304] = {0};  // 4 MB
    int run = 1; // a number of sent files.

    start = clock();
    end = clock();
    
    // Buffer for receiving data
    char buffer[RUDP_BUFFER_SIZE];
    struct sockaddr_storage sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    ssize_t received_bytes;
    int rcv_status;
    int seqnum = 0;
    do {
        rcv_status = 0;
        // Receive data chunks
        received_bytes = rudp_recv(sockfd, (struct sockaddr *)&sender_addr, &addr_len, buffer, sizeof(buffer), seqnum, &rcv_status);
        if (received_bytes < 0) {
            printf("Receive error\n");
            break;
        }
        if (rcv_status == -2) {  // if the connection was closed by the sender
            printf("Connection closed\n");
            break;
        }

        if (rcv_status == -1) {
            printf("Error receiving data\n");
            return -1;
        }

        // start the timer for the first received packet.
        if (start < end) {
            start = clock();
        }

        // if this is not the last data packet, add it to the total data    
        if (rcv_status == 1) {    
            strcat(totalData, buffer);    
            seqnum++;  
        }

        if (rcv_status == 2) { 
            // if we got the last data packet, take it and write the stats it to the file  
            seqnum = 0;  
            strcat(totalData, buffer);
            printf("Received total data length: %zu\n", strlen(totalData));
            end = clock();
            double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
            average_time += time_taken;
            float rcvdDataInMb = strlen(totalData) / (1024*1024);
            double speed = rcvdDataInMb / time_taken;
            average_speed += speed;
            fprintf(file, "Run #%d Data: Time=%f S ; Speed=%f MB/S\n", run,
                    time_taken, speed);
            memset(totalData, 0, sizeof(totalData));
            run++;        
        }
    } while (rcv_status >= 0);    
    

    // print stats    
    // add the average time and speed to the file
    fprintf(file, "\n");
    fprintf(file, "Average time: %f S\n", average_time / (run - 1));
    fprintf(file, "Average speed: %f MB/S\n", average_speed / (run - 1));

    // end the file with nice message
    fprintf(file, "\n\n-----------------------------\n");
    fprintf(file, "Thank you for using our RUDP service\n");
    rewind(file);
    char print_buffer[100];
    while (fgets(print_buffer, 100, file) != NULL) {
        printf("%s", print_buffer);
    }

    // Close the file
    fclose(file);
    remove("stats");

    return 0;
}

void usage(char *progname) {
    printf("Usage: %s -p <Port>\n", progname);
    printf("Example: %s -p 12345\n", progname);
}
