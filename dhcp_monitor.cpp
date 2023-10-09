#include <iostream>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <cstdlib>
#include "dhcp_monitor.h"
#include <netinet/ip.h>
#include <netinet/udp.h>

#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNACK 6
#define DHCPRELEASE 7

void DHCP_monitor(std::string filename, std::string interface)
{
    pcap_t *handle;

    if (filename != "NULL") // if we have file -r
    {
        handle = Open_pcap_offline(filename);
    }
    else if (interface != "NULL") // if we have interface -i
    {
        handle = Open_pcap_live(interface);
    }
}

void Packet_caller(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    std::cout << "Packet captured" << std::endl;
    static int count = 1;
    fprintf(stdout, "%d, ", count);
    fflush(stdout);
    count++;
}

pcap_t *Open_pcap_live(std::string interface)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    std::string filter = "port 67 or port 68";
    bpf_program fp;

    handle = pcap_open_live(interface.c_str(), BUFSIZ, 0, 1000, errbuf);
    if (handle == nullptr)
    {
        Exit_program("Couldn't open device");
    }
    if (pcap_compile(handle, &fp, filter.c_str(), 0, 0) == -1)
    {
        Exit_program("Couldn't parse filter");
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        Exit_program("Couldn't install filter");
    }
    pcap_loop(handle, -1, Packet_caller, NULL);
    pcap_close(handle);
    return handle;
}

pcap_t *Open_pcap_offline(std::string filename)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(filename.c_str(), errbuf);
    if (handle == NULL)
    {
        Exit_program("Could not open file");
    }
    return handle;
}

void Exit_program(const std::string &message)
{
    fprintf(stderr, "%s \n", message.c_str());
    exit(1);
}