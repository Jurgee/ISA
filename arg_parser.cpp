// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)
// Description: Agrument parser

#include "arg_parser.h"

// func to valid correct format of ip adress
bool is_IPv4_valid(std::vector<std::string> &addresses, char *ip_address)
{
    // Define a regular expression pattern for IPv4 with CIDR notation
    std::regex IPv4_with_CIDR_pattern("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}$"); //CIDR notation "0.0.0.0/24"

    // Check each IP address in the vector
    if (!std::regex_match(std::string(ip_address), IPv4_with_CIDR_pattern))
    {
        return false; // If any IP is invalid, return false
    }

    addresses.push_back(std::string(ip_address));
    return true; // All IPs are valid
}

// main parse function
struct arguments arg_parse(int argc, char *const *argv)
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
            exit_program("Unknown option.");
        }
    }
    for (int i = optind; i < argc; i++)
    {
        if (!is_IPv4_valid(args.IP_prefixes, argv[i]))
        {
            exit_program("Some or all IP addresses are not valid."); // invalid ip adress
        }
    }

    validate(&args);
    return args;
}

// print help
void print_help()
{
    std::cerr << "./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ] \n \
            -r <filename> - statistika bude vytvořena z pcap souborů \n \
            -i <interface> - rozhraní, na kterém může program naslouchat \n \
            <ip-prefix> - rozsah sítě pro které se bude generovat statistika "
              << std::endl;
    return;
}

// validate input
void validate(struct arguments *args)
{
    if (args->filename == "NULL" && args->interface == "NULL")
    {
        print_help();
        exit_program("You must specify either a filename or an interface.");
    }
    if (args->filename != "NULL" && args->interface != "NULL")
    {
        print_help();
        exit_program("You must specify either a filename or an interface, not both.");
    }
    if (args->IP_prefixes.size() == 1)
    {
        print_help();
        exit_program("You must specify at least one IP prefix.");
    }
    else
    {
        args->IP_prefixes.erase(args->IP_prefixes.begin());
    }
}
