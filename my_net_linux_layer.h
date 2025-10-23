#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
// Global socket variable
int32_t sock = -1;
char* iface_name_global;
// Initialize raw socket and bind to interface by name
int net_raw_init(char* iface_name)
{
    iface_name_global = iface_name;
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ-1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl SIOCGIFINDEX");
        close(sock);
        sock = -1;
        return -1;
    }
    int ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        perror("bind");
        close(sock);
        sock = -1;
        return -1;
    }

    return 0;
}

// Send raw Ethernet II frame from buf[len], specifying destination MAC
// Return bytes sent or -1 on error (errno set)
ssize_t l_net_send_raw_packet(uint8_t* buf, size_t len, const char* iface_name, const uint8_t dest_mac[6])
{
    if (sock == -1) {
        fprintf(stderr, "Socket not initialized\n");
        errno = EBADF;
        return -1;
    }

    // Get interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl SIOCGIFINDEX");
        return -1;
    }

    struct sockaddr_ll socket_address = {0};
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_ifindex = ifr.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, dest_mac, ETH_ALEN);

    // Send to link-layer address
    ssize_t bytes_sent = sendto(sock, buf, len, 0,
                                (struct sockaddr*)&socket_address,
                                sizeof(socket_address));
    if (bytes_sent == -1) {
        perror("sendto");
    }

    return bytes_sent;
}
int net_send_raw_packet(uint8_t* buf, size_t len)
{
   uint8_t dest_mac[6];
    memcpy(dest_mac, buf, 6);
   
   l_net_send_raw_packet(buf, len, iface_name_global, dest_mac);
}

//return num of bytes sent or -1 if error and set errno
size_t net_receve_raw_packet(uint8_t* buf)
{
    return recvfrom(sock, buf, 1522, 0, NULL, NULL);
}


// Close raw socket
int net_raw_close()
{
    if (sock != -1) {
        close(sock);
        sock = -1;
    }
    return 0;
}
