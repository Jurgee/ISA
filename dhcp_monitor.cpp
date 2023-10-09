#include <iostream>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <cstdlib>
#include "dhcp_monitor.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>



void DHCP_monitor(std::string filename, std::string interface)
{
    if (filename != "NULL") // if we have file -r
    {
        Open_pcap_offline(filename);
    }
    else if (interface != "NULL") // if we have interface -i
    {
        Open_pcap_live(interface);
    }
}

void Packet_caller(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *ethernet = (struct ether_header *)packet;

    (void)user_data;
    (void)header;

    if (ntohs(ethernet->ether_type) == ETHERTYPE_IP)
    {
        struct dhcp_packet *dhcp = (struct dhcp_packet *)(packet + sizeof(struct udphdr) + sizeof(struct ip) + sizeof(struct ether_header));
        if(dhcp->options[6] == DHCPACK)
        {
            std::cout << "DHCPACK" << std::endl;
            dhcp->yiaddr;
        }
        
    }
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