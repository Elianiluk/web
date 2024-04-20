#include "RUDP_API.h"
#include <time.h>

// Assume a maximum payload size for simplicity
#define MAX_PAYLOAD_SIZE 1492 // 1500 bytes - 8 bytes for the header

// Simplified RUDP packet structure
typedef struct {
    rudp_header header;
    char payload[MAX_PAYLOAD_SIZE];
} rudp_packet;

// Acknowledgment structure
typedef struct {
    rudp_header header;
} rudp_ack;

int set_timeout(int socket, int time) {
  // set timeout for the socket
  struct timeval timeout;
  timeout.tv_sec = time;
  timeout.tv_usec = 0;

  if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
    printf("Error setting timeout for socket");
    return FAILURE;
  }
  return SUCCESS;
}

// Helper function for a simple checksum calculation.
uint16_t simple_checksum(void *data, size_t len) {
    uint8_t *bytes = (uint8_t *)data; // Cast data pointer to a byte pointer for byte-by-byte processing
    uint32_t sum = 0; // Use a 32-bit integer to accumulate the sum to prevent overflow

    for (size_t i = 0; i < len; ++i) {
        sum += bytes[i];
    }

    // Reduce the sum to 16 bits by adding the carry (if any) back into the sum
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)sum; // Cast and return the sum as a 16-bit value
}

int rudp_socket(int domain, int type, int protocol, int isSender) {
    int sockfd = socket(domain, SOCK_DGRAM, protocol); // Use UDP
    if (sockfd < 0) {
        printf("Socket creation failed");
        return FAILURE;
    }

    int timeout = (isSender == 1) ? SENDER_TIMEOUT : RECEIVER_SOCKET_TIMEOUT;    
    set_timeout(sockfd, timeout);

    return sockfd;
}

/**
 * Waits for an acknowledgment after sending a packet.
 * 
 * @param sockfd The socket file descriptor.
 * @param seqnum The sequence number of packet we expect to get
 * @param timeout The timeout
 * @return 0 on success, -1 on failure (timeout or error). * 
 */
int wait_for_ack(int sockfd, int seqnum, int timeout) {
    clock_t starttime = clock();
    rudp_packet packet;
    struct sockaddr_storage sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    while ((double)(clock() - starttime) / CLOCKS_PER_SEC < timeout) {
        ssize_t recv_len = recvfrom(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&sender_addr, &addr_len);
        
        if (recv_len == -1) {
            printf("wait_for_ack(%d) returned FAILURE\n", seqnum);
            return FAILURE;
        }        

        // if packet.header.seqnum > seqnum, it means
        // the receiver has already got the packet with the seqnum
        // but the sender didn't get the ack for the seqnum
        if (packet.header.seqnum >= seqnum && (packet.header.flags & ACK) == ACK) {   
            return SUCCESS;
        }
    }
    printf("wait_for_ack(%d) returned FAILURE\n", seqnum);
    return FAILURE; // Timeout or error
}

ssize_t rudp_send(int sockfd, const struct sockaddr *dest_addr, socklen_t addrlen, const void *buf, size_t len, int sendFin) {
    size_t totalSent = 0; // Total bytes sent
    int attempts = 0; // Retransmission attempts
    int seqnum = 0;

    while (totalSent < len) {
        size_t chunkSize = (sendFin > 0 || len - totalSent > MAX_PAYLOAD_SIZE) ? MAX_PAYLOAD_SIZE : len - totalSent;
        rudp_packet packet;
        // Prepare the packet
        packet.header.length = htons(chunkSize);
        if (sendFin > 0) {
            packet.header.flags = sendFin;
        } else {
            packet.header.flags = DATA;
            // if we send the last packet, set the FIN flag
            if ((len - totalSent) <= sizeof(rudp_packet)) {
                packet.header.flags = packet.header.flags | FIN;
            }       
        } 
        packet.header.seqnum = seqnum;
        packet.header.checksum = 0; // set to zero to calculate checksum
        if (sendFin > 0) {
            memset(packet.payload, 0, MAX_PAYLOAD_SIZE);
        } else {
            memcpy(packet.payload, (char *)buf + totalSent, chunkSize);
        }
        packet.header.checksum = simple_checksum(&packet, sizeof(rudp_header) + chunkSize);
        // Send the packet
        ssize_t sent = sendto(sockfd, &packet, sizeof(rudp_header) + chunkSize, 0, dest_addr, addrlen);        
        if (sent < 0) {
            printf("sendto failed\n");
            return FAILURE;
        }
        // Wait for acknowledgment
        if (wait_for_ack(sockfd, seqnum, ACK_TIMEOUT) == 0) {
            totalSent += (sizeof(rudp_header) + chunkSize); // Acknowledged
            seqnum++;
            attempts = 0; // Reset attempts after successful send
        } else {
            attempts++;
            if (attempts >= MAX_RETRANS_ATTEMPTS) { // Maximum retransmission attempts
                printf("Maximum retransmission attempts reached.\n");
                return FAILURE;
            }
        }        
    }    
    return totalSent;
}

/**
 * Sends an acknowledgment (ACK) back to the sender.
 * 
 * @param sockfd The socket file descriptor.
 * @param dest_addr The address to send the ACK to.
 * @param addrlen The length of the address.
 * @param ack_flag The flag to indicate ACK type.
 * @return ssize_t Number of bytes sent, or -1 on error.
 */
ssize_t send_ack(int sockfd, const struct sockaddr *dest_addr, socklen_t addrlen, uint8_t ack_flags, int seqnum) {
    rudp_packet ack_packet;
    memset(&ack_packet, 0, sizeof(rudp_packet));
    ack_packet.header.flags = ack_flags; // Set flags
    ack_packet.header.seqnum = seqnum;
    ack_packet.header.checksum = 0;
    ack_packet.header.checksum = simple_checksum(&ack_packet, sizeof(rudp_packet));   
        
    // Send the ACK packet
    ssize_t sent = sendto(sockfd, &ack_packet, sizeof(rudp_packet), 0, dest_addr, addrlen);
    if (sent < 0) {
        printf("sendto (ACK) failed\n");
    }
    return sent;
}

ssize_t rudp_recv(int sockfd, struct sockaddr *src_addr, socklen_t *addrlen, void *buf, size_t len, int seqnum, int *status) {
    *status = -1;
    char packet[RUDP_BUFFER_SIZE];    
    ssize_t received = recvfrom(sockfd, packet, sizeof(packet), 0, src_addr, addrlen);
    if (received < 0) {
        printf("recvfrom failed\n");        
        return FAILURE;
    }

    // Extract the header and data from the received packet
    rudp_header *header = (rudp_header*) packet;
    void *data = packet + sizeof(rudp_header);
    ssize_t data_len = received - sizeof(rudp_header);

    // Verify the checksum
    uint16_t received_checksum = header->checksum;
    header->checksum = 0; // Temporarily set to zero to calculate checksum
    uint16_t calculated_checksum = simple_checksum(packet, received);
    if (received_checksum != calculated_checksum) {
        printf("Checksum mismatch. Packet corrupted.\n");
        return FAILURE;
    }

    // If the packet is valid, copy the data to the user buffer
    if (data_len > len) {
        printf("Buffer too small to hold received data.\n");
        return FAILURE;
    }
    memcpy(buf, data, data_len);    

    if ((header->flags & SYN) == SYN) {  // connection request
        printf("Received connection request\n");
        *status = 0;        
        // Send an acknowledgment back to the sender
        if (send_ack(sockfd, src_addr, *addrlen, ACK | SYN, seqnum) < 0) {
            return FAILURE; // Failed to send ACK
        }                
        return received;
    } else {
        // Send an acknowledgment back to the sender
        if (send_ack(sockfd, src_addr, *addrlen, ACK, seqnum) < 0) {
            return FAILURE; // Failed to send ACK
        }
    }

    if (header->seqnum == seqnum) {
        if (header->flags == (DATA | FIN)) {  // last packet
            *status = 2;            
        } else if (header->flags == DATA) { // data packet, not last
            *status = 1;
        } else if (header->flags == FIN) {  // close request
            *status = -2;            
        }
    } else {  
        *status = 0; // we got a packet with the wrong sequence number.
    }
    return received; // Return the length of the received data (including the header)
}

int rudp_close(int sockfd) {
    return close(sockfd);
}
