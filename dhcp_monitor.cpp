#include <iostream>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <cstdlib>
#include "dhcp_monitor.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <map>
#include "arg_parser.h"

std::vector<std::string> ipPrefixes; // Declare ipPrefixes as a global variable

void DHCP_monitor(int argc, char *argv[])
{
    struct arguments args = Arg_parse(argc, argv);
    ipPrefixes = args.ipPrefixes;

    if (args.filename != "NULL") // if we have file -r
    {
        Open_pcap_offline(args.filename);
    }
    else if (args.interface != "NULL") // if we have interface -i
    {
        Open_pcap_live(args.interface);
    }
}

void Packet_caller(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct ether_header *ethernet = (struct ether_header *)packet;
    struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl << 2));

    (void)user_data;
    (void)header;

    if (ntohs(ethernet->ether_type) == ETHERTYPE_IP)
    {
        if (udp_header->uh_sport == htons(67) || udp_header->uh_dport == htons(68))
        {
            struct dhcp_packet *dhcp = (struct dhcp_packet *)(packet + sizeof(struct udphdr) + sizeof(struct ip) + sizeof(struct ether_header));
            if (dhcp->options[6] == DHCPACK)
            {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(dhcp->yiaddr.s_addr), ip_str, INET_ADDRSTRLEN);

                calculate_overlapping_prefix_utilization(ip_str);
            }
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

bool isIPAddressInSubnet(const std::string &ip, const std::string &subnet)
{
    struct in_addr ipAddr, networkAddr, subnetMask;

    // Parse the IP address
    if (inet_pton(AF_INET, ip.c_str(), &ipAddr) != 1)
    {
        std::cerr << "Invalid IP address format: " << ip << std::endl;
        return false;
    }

    // Parse the subnet and calculate subnet mask
    size_t slashPos = subnet.find('/');
    if (slashPos == std::string::npos)
    {
        std::cerr << "Invalid subnet format: " << subnet << std::endl;
        return false;
    }

    std::string subnetIP = subnet.substr(0, slashPos);
    int prefixLength = std::stoi(subnet.substr(slashPos + 1));

    // Parse the subnet IP address
    if (inet_pton(AF_INET, subnetIP.c_str(), &networkAddr) != 1)
    {
        std::cerr << "Invalid subnet IP format: " << subnetIP << std::endl;
        return false;
    }

    // Calculate the subnet mask
    subnetMask.s_addr = htonl(0xFFFFFFFF << (32 - prefixLength));

    // Calculate the network address for the subnet
    struct in_addr subnetAddress;
    subnetAddress.s_addr = networkAddr.s_addr & subnetMask.s_addr;

    // Check if the IP address falls within the subnet
    if ((ipAddr.s_addr & subnetMask.s_addr) == subnetAddress.s_addr)
    {
        return true; // IP address is within the subnet
    }
    else
    {
        return false; // IP address is not within the subnet
    }
}

void calculate_overlapping_prefix_utilization(std::string ip_str)
{
    std::vector<IPInfo> IPInfos = Convert_to_IP_info(ipPrefixes);
    // Iterate through the IPInfo objects
    for (IPInfo &info : IPInfos)
    {
        if (isIPAddressInSubnet(ip_str, info.ip_full_name))
        {
            // Increment the count for the prefix in IPInfo
            info.allocated_addresses++;

            // Update utilization if needed
            info.utilization = (static_cast<double>(info.allocated_addresses) / static_cast<double>(info.max_hosts)) * 100.0;
        }
    }

    // Print the updated information
    std::cout << "IP-Prefix Max-hosts Allocated addresses Utilization" << std::endl;
    for (const IPInfo &info : IPInfos)
    {
        std::cout << info.ip_name << " " << info.max_hosts << " " << info.allocated_addresses << " " << info.utilization << "%" << std::endl;
    }
    exit(0);
}
