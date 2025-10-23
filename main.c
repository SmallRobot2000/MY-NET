#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <stdbool.h>
#include <string.h>

#include "my_net_linux_layer.h"
#include "my_net.h"
uint8_t packet_full[1024]; //big buffer
void test_one()
{
   
   uint8_t *packet_UDP = malloc(256); //smoler buffer
   uint8_t *packet_IPV4 = malloc(512); //smol buffer

   uint8_t *data = "OMG this is so cool!!!";

   struct net_UDP_packet pack_UDP;
   pack_UDP.dstPort = 50000;
   pack_UDP.srcPort = 50000;
   
   net_create_UDP_packet(&pack_UDP, data, strlen(data), packet_UDP);

   struct net_IPv4_packet pack_ipv4;
   pack_ipv4.dscp = 0;
   //pack_ipv4.dstAdd
   pack_ipv4.ECN = 0;
   pack_ipv4.flags = 2; //Dont fragment
   pack_ipv4.fragOff = 0;

   pack_ipv4.ID = 0x4567;
   pack_ipv4.ihr = 5;
   pack_ipv4.opt = 0;
   pack_ipv4.ver = 4;
   pack_ipv4.prot = NET_IPV4_PROT_UDP;
   pack_ipv4.TTL = 64;

   pack_ipv4.srcAdd = (192 << 24) | (168 << 16) | (2 << 8) | 100;
   pack_ipv4.dstAdd = (192 << 24) | (168 << 16) | (2 << 8) | 200;
   //pack_ipv4.dstAdd = (192 << 24) | (168 << 16) | (2 << 8) | 255;

   net_create_ipv4_packet(&pack_ipv4, packet_UDP, pack_UDP.length, packet_IPV4);

   net_create_frame(packet_full, 0x46d680cb64df, 0x9e1494c96d7e, NET_FRAME_PROT_IPV4, packet_IPV4, pack_ipv4.len);
   //net_create_frame(packet_full, 0xFFFFFFFFFFFF, 0x9e1494c96d7e, NET_FRAME_PROT_IPV4, packet_IPV4, pack_ipv4.len);

   net_send_raw_packet(packet_full, pack_ipv4.len + 14);


}

FILE *log_fd;
int32_t main(int32_t argc, int8_t *argv[])
{

   net_raw_init("veth0");

   log_fd = fopen("log.bin", "w");

   test_one();

   fwrite(packet_full, 1, 1024, log_fd);
   //while(1)
   //{
   //   loop();
   //}
   fclose(log_fd);
   
   net_raw_close();
   return 0;
}


uint8_t buf[65536];
void loop()
{

      int bytes = net_receve_raw_packet(buf);
      if (bytes < 0)
      {
         printf("error in receve packet\n");
         exit;
         return;
      }


      test(buf);
      fseek(log_fd, 0, SEEK_SET);
      fwrite(buf, sizeof(int8_t), bytes, log_fd);
      
}

char *prot_name(uint8_t ID)
{
   static char str[20];
   switch (ID)
   {
   case NET_IPV4_PROT_ICMP:
      return "ICMP";
   case NET_IPV4_PROT_IGMP:
      return "IGMP";
   case NET_IPV4_PROT_TCP:
      return "TCP";
   case NET_IPV4_PROT_UDP:
      return "UDP";
   default:
      snprintf(str, 20, "0x%x", ID);
      return str;
   }
}
void test(uint8_t *packet)
{
   //Testing space called every new packet
   struct net_IPv4_packet ipv4_packet;
   printf("Got packet");
   if(net_frame_getProtocolID(packet) == NET_FRAME_PROT_IPV4)
   {
      net_ipv4_parseHeader(NET_GET_FRAME_PAYLOAD(packet), &ipv4_packet);
      printf("\nIPv4 packet:\n");
      printf("Sender %u.%u.%u.%u\n", (ipv4_packet.srcAdd&0xFF000000)>>24, (ipv4_packet.srcAdd&0xFF0000)>>16, (ipv4_packet.srcAdd&0xFF00)>>8, (ipv4_packet.srcAdd&0xFF));
      printf("Recever %u.%u.%u.%u\n", (ipv4_packet.dstAdd&0xFF000000)>>24, (ipv4_packet.dstAdd&0xFF0000)>>16, (ipv4_packet.dstAdd&0xFF00)>>8, (ipv4_packet.dstAdd&0xFF));
      printf("ID: %x\n", ipv4_packet.ID);
      printf("IHR: %d\n", ipv4_packet.ihr);
      printf("Lengh: %d\n", ipv4_packet.len);
      printf("Protocol %s\n", prot_name(ipv4_packet.prot));
      printf("\n");
      if(ipv4_packet.prot == NET_IPV4_PROT_UDP)
      {
         struct net_UDP_packet UDP_packet;
         net_udp_parseHeader(ipv4_packet.payload, &UDP_packet);
         
         printf("Destination port: %d\n", UDP_packet.dstPort);
         printf("Source port: %d\n", UDP_packet.srcPort);
         printf("Lenght(with header): %d\n", UDP_packet.length);
      }
   }
   

   
}

//Commands
//Make 2 connected interfaces:
//sudo ip link add <p1-name> type veth peer name <p2-name>
//Disable interface
//sudo ip link set <interface_name> down
//Delete link
//sudo ip link delete <name>
//Assign ip
//sudo ip addr add 192.168.1.100/24 dev eth0
//Listen UDP
//sudo nc -u -l -s <IP> -p <port>
//Listen all
//sudo tcpdump -i <iface> -vv
//Send UDP
//echo "message" | nc -u -w1 <destination_ip> <port>