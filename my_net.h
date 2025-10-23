#include <stdint.h>
#include <stdlib.h>
#include <string.h>
extern int net_raw_init(char* iface_name); //Init NET interface
extern int net_send_raw_packet(uint8_t* buf, size_t len); //return 0 or -1 if error and set errno
extern size_t net_receve_raw_packet(uint8_t* buf);  //return num of bytes sent or -1 if error and set errno

//Helper functions

//Gets uint16_t from buffer at offset off - BIG ENDIAN
uint16_t _getFromOff_u16(int8_t* buf, int off)
{  
   return ((uint16_t)buf[off] << 8) | buf[off + 1];
}

//Gets uint32_t from buffer at offset off - BIG ENDIAN
uint32_t _getFromOff_u32(int8_t* buf, int off)
{  
   return ((uint32_t)buf[off] << 24) |
      ((uint32_t)buf[off + 1] << 16) |
      ((uint32_t)buf[off + 2] << 8)  |
      (uint32_t)buf[off + 3];
}

// Compute 16-bit one's complement checksum for given data buffer
uint16_t _ones_complement_checksum(const uint8_t *buf, size_t len) {
    uint32_t sum = 0;
    size_t i;

    // Sum all 16-bit words
    for (i = 0; i < len; i += 2) {
        uint16_t word = (buf[i] << 8) + buf[i+1];
        sum += word;
    }

    // Add carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    return (uint16_t)(~sum);
}

//Ethernet ii frame

// Gets pointer to payload of Ethernet ii buffer (offset of 14 bytes)
#define NET_GET_FRAME_PAYLOAD(frame) ((uint8_t *)(frame) + 14)

//Gets protocol "ID" from Ethernet ii frame
uint16_t net_frame_getProtocolID(uint8_t* buf)
{
   return _getFromOff_u16(buf, 12);
}

//Protocol ID in Ethernet ii frame
#define NET_FRAME_PROT_IPV4 0x0800
#define NET_FRAME_PROT_IPV6 0x86DD //Not used
#define NET_FRAME_PROT_ARP 0x0806


//IPv4

//Protocol ID in IPV4 packet
#define NET_IPV4_PROT_ICMP  0x01
#define NET_IPV4_PROT_IGMP  0x02
#define NET_IPV4_PROT_TCP   0x06
#define NET_IPV4_PROT_UDP   0x11 //17

struct net_IPv4_packet
{
    uint8_t ver; //Shoud be 4
    uint8_t ihr; //Internet Header Length - min 5
    uint8_t dscp; //Differentiated Services Code Point - priority of a packet higher value = higher priority and lower latency
    uint8_t ECN; //Explicit Congestion Notification - same byte as DSCP, describes if a device is capable of ECN(Not used)
    uint16_t len; //Total lenght of IPv4 packet min 20 - Header + data with fragments
    uint16_t ID; //This packets Identification Number
    uint8_t flags; // bits: R DF MF | R - Reserved(0) | DF - Dont fragment | MF - More fragments (not the last fragment)
    uint16_t fragOff; //Fragment offset in 8 byte blocks(64 bits) of full datagram start(ignores header)
    uint8_t TTL; //Time to live in seconds
    uint8_t prot; //Protocol ID (TCP UDP ...) here defined as NET_IPV4_PROT_XXXX
    uint16_t chksum; //Header chek sum 16-bit ones complement
    uint32_t srcAdd; //Source address
    uint32_t dstAdd; //Destination address
    uint8_t* opt; //Options if IHR > 5 (not used)
    uint8_t* payload; //pointer to packet data
};
int net_ipv4_parseHeader(uint8_t *packet, struct net_IPv4_packet *hdr)
{

    // Version and IHL share first byte
    hdr->ver = (packet[0] >> 4) & 0x0F;
    hdr->ihr = packet[0] & 0x0F;

    // DSCP and ECN share second byte
    hdr->dscp = (packet[1] >> 2) & 0x3F;
    hdr->ECN  = packet[1] & 0x03;

    // Total length and ID (big-endian)
    hdr->len = ((uint16_t)packet[2] << 8) | packet[3];
    hdr->ID  = ((uint16_t)packet[4] << 8) | packet[5];

    // Flags (3 bits) and Fragment Offset (13 bits)
    uint16_t flagsFrag = ((uint16_t)packet[6] << 8) | packet[7];
    hdr->flags   = (flagsFrag >> 13) & 0x07;
    hdr->fragOff = flagsFrag & 0x1FFF;

    // Remaining single-byte fields
    hdr->TTL    = packet[8];
    hdr->prot   = packet[9];
    hdr->chksum = ((uint16_t)packet[10] << 8) | packet[11];

    // IP addresses (big-endian)
    hdr->srcAdd = ((uint32_t)packet[12] << 24) | ((uint32_t)packet[13] << 16) |
                  ((uint32_t)packet[14] << 8) | packet[15];

    hdr->dstAdd = ((uint32_t)packet[16] << 24) | ((uint32_t)packet[17] << 16) |
                  ((uint32_t)packet[18] << 8) | packet[19];

    // Option pointer if IHL > 5
    hdr->opt = (hdr->ihr > 5) ? &packet[20] : NULL;

    // Payload starts after the header (IHL * 4 bytes)
    hdr->payload = &packet[hdr->ihr * 4];
    return 0; // success
}

//UDP
struct net_UDP_packet
{
    uint16_t srcPort;   // Source port
    uint16_t dstPort;   // Destination port
    uint16_t length;    // Length of UDP header + data
    uint16_t checksum;  // UDP checksum
    uint8_t* payload;   // Pointer to UDP payload (data)
};

int net_udp_parseHeader(uint8_t* packet, struct net_UDP_packet* hdr)
{
    hdr->srcPort = ((uint16_t)packet[0] << 8) | packet[1];
    hdr->dstPort = ((uint16_t)packet[2] << 8) | packet[3];
    hdr->length  = ((uint16_t)packet[4] << 8) | packet[5];
    hdr->checksum= ((uint16_t)packet[6] << 8) | packet[7];
    // UDP header is always 8 bytes; payload starts immediately after
    hdr->payload = &packet[8];

    return 0; // success
}

//Makes valid ethernet ii frame in buf
int net_create_frame(uint8_t *buf, uint64_t MAC_dest, uint64_t MAC_src, uint16_t prot, uint8_t *payload, size_t payload_len)
{
    //Put destination MAC address in to the frame buffer
    buf[0] = (MAC_dest & 0xFF0000000000) >> 40;
    buf[1] = (MAC_dest & 0xFF00000000) >> 32;
    buf[2] = (MAC_dest & 0xFF000000) >> 24;
    buf[3] = (MAC_dest & 0xFF0000) >> 16;
    buf[4] = (MAC_dest & 0xFF00) >> 8;
    buf[5] = (MAC_dest & 0xFF);

    //Put source MAC address in to the frame buffer
    buf[6]  = (MAC_src & 0xFF0000000000) >> 40;
    buf[7]  = (MAC_src & 0xFF00000000) >> 32;
    buf[8]  = (MAC_src & 0xFF000000) >> 24;
    buf[9]  = (MAC_src & 0xFF0000) >> 16;
    buf[10] = (MAC_src & 0xFF00) >> 8;
    buf[11] = (MAC_src & 0xFF);

    //Put protocol ID in to the frame buffer
    buf[12] = (prot & 0xFF00) >> 8;
    buf[13] = (prot & 0xFF);

    memcpy(buf+14, payload, payload_len);
}

//Creates valid ipv4 packet in the packet buffer from header and data of size data_len
//Updates hdr with data size & payload pointer
int net_create_ipv4_packet(struct net_IPv4_packet *hdr, uint8_t *data, size_t data_len, uint8_t *packet)
{
    // Version and IHL share first byte
    packet[0] = (hdr->ver << 4) | (hdr->ihr & 0x0F);

    // DSCP and ECN share second byte
    packet[1] = (hdr->dscp << 2) | (hdr->ECN & 0x03);

    //Total lenght and ID (big-endian)
    hdr->len = hdr->ihr * 4 + data_len;

    packet[2] = (hdr->len >> 8) & 0xFF;
    packet[3] = hdr->len & 0xFF;

    packet[4] = (hdr->ID >> 8) & 0xFF;
    packet[5] = hdr->ID & 0xFF;

    // Flags (3 bits) and Fragment Offset (13 bits)
    uint16_t flags_frag = (hdr->flags << 13) | (hdr->fragOff & 0x1FFF);
    packet[6] = (flags_frag >> 8) & 0xFF;
    packet[7] = (flags_frag) & 0xFF;


    // Some 8-bit values
    packet[8] = hdr->TTL;
    packet[9] = hdr->prot;

    // For computing cheksum
    packet[10] = 0;
    packet[11] = 0;

    // IP addresses (big-endian)
    packet[12] = (hdr->srcAdd >> 24) & 0xFF;
    packet[13] = (hdr->srcAdd >> 16) & 0xFF;
    packet[14] = (hdr->srcAdd >> 8) & 0xFF;
    packet[15] = (hdr->srcAdd) & 0xFF;

    packet[16] = (hdr->dstAdd >> 24) & 0xFF;
    packet[17] = (hdr->dstAdd >> 16) & 0xFF;
    packet[18] = (hdr->dstAdd >> 8) & 0xFF;
    packet[19] = (hdr->dstAdd) & 0xFF;


    // Option pointer if IHL > 5
    if(hdr->ihr > 5)
        packet[20] = hdr->opt;

    packet[10] = 0;
    packet[11] = 0;
    // Compute cheksum and update
    hdr->chksum = _ones_complement_checksum(packet, hdr->ihr*4);
    
    packet[10] = (hdr->chksum >> 8);
    packet[11] = hdr->chksum & 0xFF;

    // Payload starts after the header (IHL * 4 bytes)
    hdr->payload = packet + hdr->ihr*4;
    memcpy(hdr->payload, data, data_len);    

    return 0; // success
}

//Create UDP packet in the packet buffer from struct hdr and data
//Updates hdr with data len, pointer and cheksum
int net_create_UDP_packet(struct net_UDP_packet* hdr, uint8_t *data, size_t data_len, uint8_t* packet)
{
    
    

    // Update header total lenght
    hdr->length = 8 + data_len; //Lenght of header + data lenght

    // Update payload pointer
    hdr->payload = packet + 8; //8 bytes for header

    //Calc cheksum
    hdr->checksum = 0; //Not calculated for now

    // Source port
    packet[0] = (hdr->srcPort >> 8);
    packet[1] = hdr->srcPort & 0xFF;

    // Destination port
    packet[2] = (hdr->dstPort >> 8);
    packet[3] = hdr->dstPort & 0xFF;

    // Lenght
    packet[4] = (hdr->length >> 8);
    packet[5] = hdr->length & 0xFF;

    // Cheksum
    packet[6] = (hdr->checksum >> 8);
    packet[7] = hdr->checksum & 0xFF;

    // Payload
    memcpy(hdr->payload, data, data_len);
}