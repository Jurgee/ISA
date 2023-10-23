// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)
// Description: Main functions of the program

#include "dhcp_monitor.h"

// Define a vector to store IPInfo objects
std::vector<IPInfo> IP_infos;

// Define a set to store IP addresses that the server has already sent
std::set<std::string> sent_IPs;

// DHCP main function
void DHCP_monitor(int argc, char *argv[])
{
    openlog("dhcp-stats", LOG_PID, LOG_DAEMON); // open syslog

    struct arguments args = arg_parse(argc, argv);   // parse arguments
    IP_infos = convert_to_IP_info(args.IP_prefixes); // convert to IP info

    if (args.filename != "NULL") // if we have file -r
    {
        open_pcap_offline(args.filename);
    }
    else if (args.interface != "NULL") // if we have interface -i
    {
        open_pcap_live(args.interface);
    }
    closelog(); // Close syslog
}

// function for packets
void packet_caller(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct ether_header *ethernet = (struct ether_header *)packet;
    struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl << 2));

    (void)user_data;
    (void)header;

    if (ntohs(ethernet->ether_type) == ETHERTYPE_IP)
    {
        if (udp_header->source == htons(67) || udp_header->dest == htons(68))
        {
            struct dhcp_packet *dhcp = (struct dhcp_packet *)(packet + sizeof(struct udphdr) + sizeof(struct ip) + sizeof(struct ether_header));

            // Iterate through the DHCP options
            for (size_t i = 0; i < MAX_DHCP_OPTIONS_LENGTH; i++)
            {
                if (dhcp->options[i] == 53) // if we have DHCP message type
                {
                    if (dhcp->options[i + 2] == DHCPACK) // if we have DHCPACK
                    {
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(dhcp->yiaddr.s_addr), ip_str, INET_ADDRSTRLEN);

                        if (!check_IP_address(ip_str)) // if we have new ip adress
                        {
                            calculate_overlapping_prefix_utilization(ip_str);
                            std::sort(IP_infos.begin(), IP_infos.end(), sort_IP_info); // sort by ip_full_name
                        }
                        display_live_statistics();
                    }
                }
            }
        }
    }
}

// pcap functions --live mode
pcap_t *open_pcap_live(std::string interface)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    std::string filter = "port 67 or port 68";
    bpf_program fp;

    handle = pcap_open_live(interface.c_str(), BUFSIZ, 0, 1000, errbuf);
    if (handle == nullptr)
    {
        exit_program("Couldn't open device");
    }
    if (pcap_compile(handle, &fp, filter.c_str(), 0, 0) == -1)
    {
        exit_program("Couldn't parse filter");
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        exit_program("Couldn't install filter");
    }

    initialize_ncurses(); // Initialize ncurses
    signal(SIGINT, sigint_handler); // signal handler for SIGINT

    // Loop through the packets, wait for SIGINT
    while (true)
    {
        pcap_loop(handle, -1, packet_caller, NULL);
    }
    return nullptr;
}

// pcap functions --offline mode
pcap_t *open_pcap_offline(std::string filename)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    std::string filter = "port 67 or port 68";
    bpf_program fp;

    handle = pcap_open_offline(filename.c_str(), errbuf);
    if (handle == nullptr)
    {
        exit_program("Couldn't open device");
    }
    if (pcap_compile(handle, &fp, filter.c_str(), 0, 0) == -1)
    {
        exit_program("Couldn't parse filter");
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        exit_program("Couldn't install filter");
    }
    // Loop through the packets
    while (true)
    {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);
        if (packet != nullptr)
        {
            packet_caller(nullptr, &header, packet);
        }
        else
        {
            display_offline_statistics();
            break;
        }
    }

    pcap_close(handle); // Close the pcap handle
    return nullptr;
}

// func for address in subnet
bool is_IP_address_in_subnet(const std::string &ip, const std::string &subnet, int prefix)
{
    struct in_addr ipAddr, networkAddr, subnetMask, subnetAddress;

    // Parse the IP address
    if (inet_pton(AF_INET, ip.c_str(), &ipAddr) != 1)
    {
        exit_program("Invalid IP address format: " + ip);
    }

    // Parse the subnet IP address
    if (inet_pton(AF_INET, subnet.c_str(), &networkAddr) != 1)
    {
        exit_program("Invalid subnet IP format: " + subnet);
    }

    // Calculate the subnet mask
    subnetMask.s_addr = htonl(0xFFFFFFFF << (32 - prefix));

    // Calculate the network address for the subnet
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

// calculate utilization for each prefix
void calculate_overlapping_prefix_utilization(std::string ip_str)
{
    // Iterate through the IPInfo objects
    for (IPInfo &info : IP_infos)
    {
        if (is_IP_address_in_subnet(ip_str, info.ip_name, info.prefix))
        {
            // Increment the count for the prefix in IPInfo
            info.allocated_addresses++;

            // Update utilization if needed
            info.utilization = (static_cast<double>(info.allocated_addresses) / static_cast<double>(info.max_hosts)) * 100.0;

            // Check if utilization exceeds 50%
            if (info.utilization > 50.0)
            {
                // Log the message for the exceeded prefix
                log_exceeded_prefix(info.ip_full_name);
            }
        }
    }
}

// display statistics in ncurses window
void display_live_statistics()
{
    clear();
    printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");

    for (const IPInfo &info : IP_infos)
    {
        printw("%s %d %d %.2f%%\n", info.ip_full_name.c_str(), info.max_hosts, info.allocated_addresses, info.utilization);
    }
    refresh();
}

// display statistics in terminal
void display_offline_statistics()
{
    std::cout << "IP-Prefix Max-hosts Allocated addresses Utilization" << std::endl;

    for (const IPInfo &info : IP_infos)
    {
        std::cout << info.ip_full_name << " " << info.max_hosts << " " << info.allocated_addresses << " " << std::fixed << std::setprecision(2) << info.utilization << "%" << std::endl;
    }
}

// check if we have new ip adress
bool check_IP_address(std::string ip_str)
{
    // Check if the IP address is in the set of sent_IPs
    if (sent_IPs.find(ip_str) != sent_IPs.end())
    {
        // This IP address has already been sent, skip processing
        return true;
    }

    // Add the IP address to the set of sent_IPs
    sent_IPs.insert(ip_str);
    return false;
}

