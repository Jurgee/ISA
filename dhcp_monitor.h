// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)

#ifndef DHCP_MONITOR
#define DHCP_MONITOR

#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <cstdlib>
#include <stdint.h>
#include <vector>
#include "ip_info.h"
#include <iostream>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include "arg_parser.h"
#include <ncurses.h>
#include <syslog.h>
#include "ncurses_logger.h"
#include <set>
#include <iomanip>
#include <csignal>

#define MAX_DHCP_CHADDR_LENGTH 16
#define MAX_DHCP_SNAME_LENGTH 64
#define MAX_DHCP_FILE_LENGTH 128
#define MAX_DHCP_OPTIONS_LENGTH 312

// DHCP message types
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNACK 6
#define DHCPRELEASE 7

// struct for dhcp packet
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
};

// functions

void DHCP_monitor(int argc, char *argv[]);
void check_utilization();
void sigint_handler(int signum);
void sigterm_handler(int signum);
void check_options(struct dhcp_packet *dhcp, const u_char *options);

// pcap functions

pcap_t *open_pcap(pcap_t *handle, std::string filter, bpf_program fp);
void exit_program(const std::string &message);
void packet_caller(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
void calculate_overlapping_prefix_utilization(std::string ip_str);
bool is_IP_address_in_subnet(const std::string &ip, const std::string &subnet, int prefix);
bool check_IP_address(std::string ip_str);

// statistics functions

void display_statistics();

#endif // DHCP_MONITOR
