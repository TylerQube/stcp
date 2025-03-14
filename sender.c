/************************************************************************
 * Adapted from a course at Boston University for use in CPSC 317 at UBC
 *
 *
 * The interfaces for the STCP sender (you get to implement them), and a
 * simple application-level routine to drive the sender.
 *
 * This routine reads the data to be transferred over the connection
 * from a file specified and invokes the STCP send functionality to
 * deliver the packets as an ordered sequence of datagrams.
 *
 * Version 2.0
 *
 *
 *************************************************************************/


#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/file.h>

#include "stcp.h"

#define STCP_SUCCESS 1
#define STCP_ERROR -1

typedef struct {

    int fd;
    unsigned char state;
    unsigned short window_size;
    packet * pkt;

    /* YOUR CODE HERE */

} stcp_send_ctrl_blk;
/* ADD ANY EXTRA FUNCTIONS HERE */

unsigned char* padded_data(unsigned char* data, int len) {
    unsigned char* padded = malloc(sizeof(tcpheader) + len);
    memcpy(padded + sizeof(tcpheader), data, len);
    return padded;
}

ssize_t send_packet(stcp_send_ctrl_blk* blk, packet* pkt) {
    pkt->hdr->checksum = 0;
    htonHdr(pkt->hdr);
    pkt->hdr->checksum = ipchecksum(pkt, STCP_MTU);
    long len = payloadSize(pkt);
    logLog("segment", "sending: %d", len);
    logLog("segment", "sending packet of size: %d", pkt->len);
    return send(blk->fd, pkt->data, pkt->len, 0); 
}

/*
 * Send STCP. This routine is to send all the data (len bytes).  If more
 * than MSS bytes are to be sent, the routine breaks the data into multiple
 * packets. It will keep sending data until the send window is full or all
 * the data has been sent. At which point it reads data from the network to,
 * hopefully, get the ACKs that open the window. You will need to be careful
 * about timing your packets and dealing with the last piece of data.
 *
 * Your sender program will spend almost all of its time in either this
 * function or in tcp_close().  All input processing (you can use the
 * function readWithTimeout() defined in stcp.c to receive segments) is done
 * as a side effect of the work of this function (and stcp_close()).
 *
 * The function returns STCP_SUCCESS on success, or STCP_ERROR on error.
 */
int stcp_send(stcp_send_ctrl_blk *stcp_CB, unsigned char* data, int length) {
    if (stcp_CB->state != STCP_SENDER_ESTABLISHED) return STCP_ERROR;
    logLog("segment", "%d bytes to send", length);

    int bytes_sent = 0;
    int fd = stcp_CB->fd;

    unsigned char* packet_data;
    packet *pkt = stcp_CB->pkt;
    while(bytes_sent < length) {
        packet_data = padded_data(data, length); 
        createSegment(pkt, ACK, stcp_CB->window_size, pkt->hdr->ackNo, pkt->hdr->seqNo+1, packet_data, length);
        int s = send_packet(stcp_CB, pkt);
        logLog("segment", "sent: %d", s);
        free(packet_data);
        bytes_sent += s;

        int len = readWithTimeout(fd, pkt->hdr, STCP_MAX_TIMEOUT);
        // save checksum from network order
        unsigned short checksum = pkt->hdr->checksum;
        // set checksum to zero before verifying checksum
        pkt->hdr->checksum = 0;
        unsigned short actual_cs = ipchecksum(pkt->hdr, len);
        if(actual_cs != checksum) {
            logLog("error", "Checksum 0x%x is not 0x%x", actual_cs, checksum);
            return NULL;
        }

    }

    ntohHdr(pkt->hdr);


    return STCP_SUCCESS;
}



/*
 * Open the sender side of the STCP connection. Returns the pointer to
 * a newly allocated control block containing the basic information
 * about the connection. Returns NULL if an error happened.
 *
 * If you use udp_open() it will use connect() on the UDP socket
 * then all packets then sent and received on the given file
 * descriptor go to and are received from the specified host. Reads
 * and writes are still completed in a datagram unit size, but the
 * application does not have to do the multiplexing and
 * demultiplexing. This greatly simplifies things but restricts the
 * number of "connections" to the number of file descriptors and isn't
 * very good for a pure request response protocol like DNS where there
 * is no long term relationship between the client and server.
 */
stcp_send_ctrl_blk * stcp_open(char *destination, int sendersPort,
                             int receiversPort) {

    logLog("init", "Sending from port %d to <%s, %d>", sendersPort, destination, receiversPort);
    // Since I am the sender, the destination and receiversPort name the other side
    int fd = udp_open(destination, receiversPort, sendersPort);
    (void) fd;
    /* YOUR CODE HERE */

    unsigned short checksum;
    ssize_t s;
    stcp_send_ctrl_blk *blk = malloc(sizeof(stcp_send_ctrl_blk));
    blk->fd = fd;
    blk->state = STCP_SENDER_CLOSED;

    // Send SYN
    packet* pkt = malloc(STCP_MTU);
    blk->pkt = pkt;
    createSegment(pkt, SYN, STCP_MAXWIN, 0, 0, NULL, 0);
    pkt->hdr->checksum = 0;
    htonHdr(pkt->hdr);
    pkt->hdr->checksum = ipchecksum(pkt->hdr, STCP_MTU);
    s = send(fd, pkt, pkt->len, 0); 
    logLog("segment", "%d", s);

    blk->state = STCP_SENDER_SYN_SENT;


    logLog("segment", "sent SYN");

    // Receive SYN-ACK
    int len = readWithTimeout(fd, pkt->hdr, STCP_MAX_TIMEOUT);
    // save checksum from network order
    checksum = pkt->hdr->checksum;
    // set checksum to zero before verifying checksum
    pkt->hdr->checksum = 0;
    unsigned short actual_cs = ipchecksum(pkt->hdr, len);
    if(actual_cs != checksum) {
        logLog("error", "Checksum 0x%x is not 0x%x", actual_cs, checksum);
        return NULL;
    }

    blk->state = STCP_SENDER_ESTABLISHED;

    ntohHdr(pkt->hdr);

    createSegment(pkt, ACK, pkt->hdr->windowSize, pkt->hdr->ackNo, pkt->hdr->seqNo+1, NULL, 0);
    pkt->hdr->checksum = 0;
    htonHdr(pkt->hdr);
    pkt->hdr->checksum = ipchecksum(pkt->hdr, sizeof(tcpheader));
    s = send(fd, pkt, pkt->len, 0); 
    logLog("segment", "%d", s);

    // Receive ACK 
    len = readWithTimeout(fd, pkt->hdr, STCP_MAX_TIMEOUT);
    // save checksum from network order
    checksum = pkt->hdr->checksum;
    // set checksum to zero before verifying checksum
    pkt->hdr->checksum = 0;
    actual_cs = ipchecksum(pkt->hdr, len);
    if(actual_cs != checksum) {
        logLog("error", "Checksum 0x%x is not 0x%x", actual_cs, checksum);
        return NULL;
    }

    ntohHdr(pkt->hdr);


    return blk;
}


/*
 * Make sure all the outstanding data has been transmitted and
 * acknowledged, and then initiate closing the connection. This
 * function is also responsible for freeing and closing all necessary
 * structures that were not previously freed, including the control
 * block itself.
 *
 * Returns STCP_SUCCESS on success or STCP_ERROR on error.
 */
int stcp_close(stcp_send_ctrl_blk *cb) {
    cb->state = STCP_SENDER_CLOSING;
    packet *pkt = cb->pkt;
    int fd = cb->fd;
    createSegment(pkt, FIN, cb->window_size, pkt->hdr->ackNo, pkt->hdr->seqNo+1, NULL, 0);
    pkt->hdr->checksum = 0;
    htonHdr(pkt->hdr);
    pkt->hdr->checksum = ipchecksum(pkt, STCP_MTU);
    int s = send(fd, pkt, STCP_MTU, 0); 

    cb->state = STCP_SENDER_FIN_WAIT;

    int len = readWithTimeout(fd, pkt->hdr, STCP_MAX_TIMEOUT);
    // save checksum from network order
    unsigned short checksum = pkt->hdr->checksum;
    // set checksum to zero before verifying checksum
    pkt->hdr->checksum = 0;
    unsigned short actual_cs = ipchecksum(pkt->hdr, len);
    if(actual_cs != checksum) {
        logLog("error", "Checksum 0x%x is not 0x%x", actual_cs, checksum);
        return NULL;
    }

    cb->state = STCP_SENDER_CLOSED;
    /* YOUR CODE HERE */
    return STCP_SUCCESS;
}
/*
 * Return a port number based on the uid of the caller.  This will
 * with reasonably high probability return a port number different from
 * that chosen for other uses on the undergraduate Linux systems.
 *
 * This port is used if ports are not specified on the command line.
 */
int getDefaultPort() {
    uid_t uid = getuid();
    int port = (uid % (32768 - 512) * 2) + 1024;
    assert(port >= 1024 && port <= 65535 - 1);
    return port;
}

/*
 * This application is to invoke the send-side functionality.
 */
int main(int argc, char **argv) {
    stcp_send_ctrl_blk *cb;

    char *destinationHost;
    int receiversPort, sendersPort;
    char *filename = NULL;
    int file;
    /* You might want to change the size of this buffer to test how your
     * code deals with different packet sizes.
     */
    unsigned char buffer[STCP_MSS];
    int num_read_bytes;

    logConfig("sender", "init,segment,error,failure");
    /* Verify that the arguments are right */
    if (argc > 5 || argc == 1) {
        fprintf(stderr, "usage: sender DestinationIPAddress/Name receiveDataOnPort sendDataToPort filename\n");
        fprintf(stderr, "or   : sender filename\n");
        exit(1);
    }
    if (argc == 2) {
        filename = argv[1];
        argc--;
    }

    // Extract the arguments
    destinationHost = argc > 1 ? argv[1] : "localhost";
    receiversPort = argc > 2 ? atoi(argv[2]) : getDefaultPort();
    sendersPort = argc > 3 ? atoi(argv[3]) : getDefaultPort() + 1;
    if (argc > 4) filename = argv[4];

    /* Open file for transfer */
    file = open(filename, O_RDONLY);
    if (file < 0) {
        logPerror(filename);
        exit(1);
    }

    /*
     * Open connection to destination.  If stcp_open succeeds the
     * control block should be correctly initialized.
     */
    cb = stcp_open(destinationHost, sendersPort, receiversPort);
    if (cb == NULL) {
        logLog("error", "failed to establish TCP connection");
        exit(1);
        /* YOUR CODE HERE */
    }

    /* Start to send data in file via STCP to remote receiver. Chop up
     * the file into pieces as large as max packet size and transmit
     * those pieces.
     */
    while (1) {
        num_read_bytes = read(file, buffer, sizeof(buffer));

        /* Break when EOF is reached */
        if (num_read_bytes <= 0)
            break;

        if (stcp_send(cb, buffer, num_read_bytes) == STCP_ERROR) {
            exit(1);
            /* YOUR CODE HERE */
        }
    }

    /* Close the connection to remote receiver */
    if (stcp_close(cb) == STCP_ERROR) {
        /* YOUR CODE HERE */
        exit(1);
    }

    logLog("segment", "Successfully closed TCP connection");

    return 0;
}
