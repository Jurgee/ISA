#include <iostream>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <cstdlib>
#include <stdint.h>

#define MAX_DHCP_CHADDR_LENGTH 16
#define MAX_DHCP_SNAME_LENGTH 64
#define MAX_DHCP_FILE_LENGTH 128
#define MAX_DHCP_OPTIONS_LENGTH 312

#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNACK 6
#define DHCPRELEASE 7

struct dhcp_packet
{
    u_int8_t op;                                  /* packet type */
    u_int8_t htype;                               /* type of hardware address for this machine (Ethernet, etc) */
    u_int8_t hlen;                                /* length of hardware address (of this machine) */
    u_int8_t hops;                                /* hops */
    u_int32_t xid;                                /* random transaction id number - chosen by this machine */
    u_int16_t secs;                               /* seconds used in timing */
    u_int16_t flags;                              /* flags */
    struct in_addr ciaddr;                        /* IP address of this machine (if we already have one) */
    struct in_addr yiaddr;                        /* IP address of this machine (offered by the DHCP server) */
    struct in_addr siaddr;                        /* IP address of DHCP server */
    struct in_addr giaddr;                        /* IP address of DHCP relay */
    unsigned char chaddr[MAX_DHCP_CHADDR_LENGTH]; /* hardware address of this machine */
    char sname[MAX_DHCP_SNAME_LENGTH];            /* name of DHCP server */
    char file[MAX_DHCP_FILE_LENGTH];              /* boot file name (used for diskless booting?) */
    char options[MAX_DHCP_OPTIONS_LENGTH];        /* options */
};

void DHCP_monitor(std::string filename, std::string interface);
pcap_t *Open_pcap_live(std::string interface);
pcap_t *Open_pcap_offline(std::string filename);
void Exit_program(const std::string &message);
void Packet_caller(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);