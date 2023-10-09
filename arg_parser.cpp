#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <regex>
#include "arg_parser.h"

// func to valid correct format of ip adress
bool is_IPv4_valid(std::vector<std::string> &addresses, char *ip_address)
{
    // Define a regular expression pattern for IPv4 with CIDR notation
    std::regex ipv4WithCIDRPattern("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}$");

    // Check each IP address in the vector
    if (!std::regex_match(std::string(ip_address), ipv4WithCIDRPattern))
    {
        return false; // If any IP is invalid, return false
    }

    addresses.push_back(std::string(ip_address));
    return true; // All IPs are valid
}

// main function to parse
struct arguments Arg_parse(int argc, char *const *argv)
{
    std::vector<std::string> empty_vector{"NULL"};
    struct arguments args = {"NULL", "NULL", empty_vector};
    int opt;
    while ((opt = getopt(argc, argv, "r:i:")) != -1)
    {
        switch (opt)
        {
        case 'r':

            args.filename = optarg;
            break;
        case 'i':

            args.interface = optarg;
            break;
        case '?':
            print_help();
            exit(EXIT_FAILURE);
        }
    }

    for (int i = optind; i < argc; i++)
    {
        if (!is_IPv4_valid(args.ipPrefixes, argv[i]))
        {
            std::cout << "Some or all IP addresses are not valid." << std::endl; // invalid ip adress
            exit(EXIT_FAILURE);
        }
    }

    validate(&args);
    return args;
}

void print_help()
{
    std::cerr << "./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ] \n \
            -r <filename> - statistika bude vytvořena z pcap souborů \n \
            -i <interface> - rozhraní, na kterém může program naslouchat \n \
            <ip-prefix> - rozsah sítě pro které se bude generovat statistika "
              << std::endl;
    return;
}

void validate(struct arguments *args)
{
    if (args->filename == "NULL" && args->interface == "NULL")
    {
        print_help();
        exit(EXIT_FAILURE);
    }
    if (args->filename != "NULL" && args->interface != "NULL")
    {
        print_help();
        exit(EXIT_FAILURE);
    }
    if (args->ipPrefixes.size() == 1)
    {
        print_help();
        exit(EXIT_FAILURE);
    }
    else
    {
        args->ipPrefixes.erase(args->ipPrefixes.begin());
    }
}
