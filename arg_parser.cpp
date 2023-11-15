// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)
// Description: Argument parser functions

#include "arg_parser.h"

// func to valid correct format of ip adress
bool is_IPv4_valid(std::vector<std::string> &addresses, char *ip_address)
{
    // Define a regular expression pattern for IPv4 with CIDR notation
    std::regex IPv4_with_CIDR_pattern("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}$"); // CIDR notation "0.0.0.0/24"

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
    bool filename = false;  // if we have -r
    bool interface = false; // if we have -i

    std::vector<std::string> empty_vector{"NULL"};          // empty vector
    struct arguments args = {"NULL", "NULL", empty_vector}; // default values
    int opt;
    while ((opt = getopt(argc, argv, "r:i:")) != -1)
    {
        // parse arguments
        switch (opt)
        {
        case 'r': // -r filename
            if (filename)
            {
                print_help();
                exit_program("You can specify only one filename.");
            }
            args.filename = optarg;
            filename = true;
            break;

        case 'i': // -i interface
            if (interface)
            {
                print_help();
                exit_program("You can specify only one interface.");
            }
            args.interface = optarg;
            interface = true;
            break;

        case '?': // invalid argument
            print_help();
            exit_program("Invalid argument.");
        }
    }
    for (int i = optind; i < argc; i++)
    {
        if (!is_IPv4_valid(args.IP_prefixes, argv[i]))
        {
            exit_program("Some or all IP addresses are not valid."); // invalid ip address
        }
    }

    validate(&args);
    return args;
}

// validate input
void validate(struct arguments *args)
{
    if (args->filename == "NULL" && args->interface == "NULL") // if we dont have -r or -i
    {
        print_help();
        exit_program("You must specify either a filename or an interface.");
    }
    if (args->filename != "NULL" && args->interface != "NULL") // if we have both -r and -i
    {
        print_help();
        exit_program("You must specify either a filename or an interface, not both.");
    }
    if (args->IP_prefixes.size() == 1) // if we dont have ip adress
    {
        print_help();
        exit_program("You must specify at least one IP prefix.");
    }
    else // if we have ip adress
    {
        args->IP_prefixes.erase(args->IP_prefixes.begin());
    }
}
