// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)
// Description: Main functions of the program

#include "dhcp_monitor.h"

// Define a vector to store IP_info objects
std::vector<IPInfo> IP_infos;
// Define a set to store IP addresses that the server has already sent
std::set<std::string> sent_IPs;
// Define a pcap_t handle
pcap_t *handle;
// Define a bpf_program
bpf_program fp;

// DHCP main function
void DHCP_monitor(int argc, char *argv[])
{
    openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER); // open syslog

    signal(SIGINT, handler);                                 // signal handler for SIGINT
    signal(SIGTERM, handler);                                // signal handler for SIGTERM
    signal(SIGKILL, handler);                                // signal handler for SIGKILL

    struct arguments args = arg_parse(argc, argv);   // parse arguments
    IP_infos = convert_to_IP_info(args.IP_prefixes); // convert to IP info

    char errbuf[PCAP_ERRBUF_SIZE];
    std::string filter = "port 67 or port 68";

    if (args.filename != "NULL") // if we have file -r
    {
        handle = pcap_open_offline(args.filename.c_str(), errbuf);
        open_pcap(handle, filter, fp);
    }
    else if (args.interface != "NULL") // if we have interface -i
    {
        handle = pcap_open_live(args.interface.c_str(), BUFSIZ, 0, 1000, errbuf);
        open_pcap(handle, filter, fp);
    }
}

// func for open pcap
pcap_t *open_pcap(pcap_t *handle, std::string filter, bpf_program fp)
{
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

    // Loop through the packets, wait for SIGINT
    while (true)
    {
        pcap_loop(handle, -1, packet_caller, NULL);
    }
    return nullptr;
}

// function for packets
void packet_caller(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)user_data; // Suppress unused variable warning
    (void)header;    // Suppress unused variable warning

    struct ip *ip_header = (struct ip *)(packet + 14);                                    // Point to the IP header
    struct ether_header *ethernet = (struct ether_header *)packet;                        // Point to the Ethernet header

    struct dhcp_packet *dhcp = (struct dhcp_packet *)(packet + sizeof(struct udphdr) + sizeof(struct ip) + sizeof(struct ether_header)); 
    const u_char *options = (packet + sizeof(struct udphdr) + sizeof(struct ip) + sizeof(struct ether_header) + sizeof(dhcp_packet) + 4); // Point to the start of DHCP options + 4 bytes of magic cookie
    int options_lenght =  ip_header->ip_len + 14 - (sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dhcp_packet)); // Calculate the length of the options
     
    if (ntohs(ip_header->ip_len) < (sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dhcp_packet))) // Check if the packet is large enough for DHCP
    {
        return; // Skip processing
    }

    if ((ntohs(ethernet->ether_type) == ETHERTYPE_IP)) // Check if the packet is IPv4 and UDP
    {
        check_options(dhcp, options, options_lenght); // Check the options
    }
    display_statistics(); // Display empty statistics
}

// func for check options in DHCP packet
void check_options(struct dhcp_packet *dhcp, const u_char *options,  int options_lenght)
{
    while (options[0] != 255 && options_lenght > 0) // The end of options is marked with 255 (0xFF in hexadecimal) and the length of the options is greater than 0
    {
        char option_code = options[0];   // The first byte of the option is the option code
        char option_length = options[1]; // The second byte of the option is the option length

        if (option_code == 53 && option_length == 1 && options[2] == DHCPACK) // Check if the option code is 53 (DHCP message type) and check if the DHCPACK is set
        {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(dhcp->yiaddr.s_addr), ip_str, INET_ADDRSTRLEN);

            if (strcmp(ip_str, "0.0.0.0") == 0) // yiaddr is 0.0.0.0, it is DHCPINFORM
            {
                break; // Skip processing
            }

            if (!check_IP_address(ip_str)) // Check if the IP address has already been sent
            {
                calculate_overlapping_prefix_utilization(ip_str); // Calculate the utilization for the IP address
            }
            display_statistics(); // Display the statistics
            break;
        }
        options += (option_length + 2); // Move to the next option
        options_lenght -= (option_length + 2); // Decrease the length of the options
    }
}

// func for check if IP address is in subnet
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
    if ((ipAddr.s_addr & subnetMask.s_addr) == subnetAddress.s_addr &&                                             // Check if the IP address is in the subnet
        (ipAddr.s_addr != subnetAddress.s_addr) && (ipAddr.s_addr != (subnetAddress.s_addr | ~subnetMask.s_addr))) // Check if the IP address is not the network address or the broadcast address
    {
        return true; // IP address is within the subnet
    }
    else
    {
        return false; // IP address is not within the subnet
    }
}

// calculate utilization for each IP adress
void calculate_overlapping_prefix_utilization(std::string ip_str)
{
    // Iterate through the IPInfo objects
    for (IPInfo &info : IP_infos)
    {
        if (is_IP_address_in_subnet(ip_str, info.ip_name, info.prefix))
        {
            if (info.utilization < 100.0) // Check if the utilization is not 100%
            {
                // Increment the count for the prefix in IPInfo
                info.allocated_addresses++;

                // Update utilization if needed
                info.utilization = (static_cast<double>(info.allocated_addresses) / static_cast<double>(info.max_hosts)) * 100.0;
            }
        }
    }
}

// func for display statistics
void display_statistics()
{
    std::sort(IP_infos.begin(), IP_infos.end(), sort_IP_info); // Sort the IPInfo objects
    
    // Iterate through the IPInfo objects
    for (size_t i = 0; i < IP_infos.size(); ++i)
    {
        move(i + 1, 0); // Move to the next line after the header
        clrtoeol();     // Clear the line
        printw("%s %u %u %.2f%%\n", IP_infos[i].ip_full_name.c_str(), IP_infos[i].max_hosts, IP_infos[i].allocated_addresses, IP_infos[i].utilization);
    }

    check_utilization();
    refresh();
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

// check utilization if it is over 50%
void check_utilization()
{
    for (IPInfo &info : IP_infos)
    {
        // Check if utilization exceeds 50%
        if (info.utilization > 50.0)
        {
            // Log the message for the exceeded prefix
            log_exceeded_prefix(info.ip_full_name);
        }
    }
}

// signal handler for SIGINT, SIGTERM, SIGKILL
void handler(int signum)
{
    (void)signum;
    cleanup_ncurses();
    pcap_close(handle);
    pcap_freecode(&fp);
    closelog();
    output_log();
    exit(0);
}

