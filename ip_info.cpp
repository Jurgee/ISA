// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)
// Description: IP info struct and functions

#include "ip_info.h"

// convert vector of strings to vector of IPInfo
std::vector<IPInfo> convert_to_IP_info(const std::vector<std::string> &prefixes)
{
    std::vector<IPInfo> IP_infos;
    for (const std::string &prefix : prefixes)
    {
        size_t slash_pos = prefix.find_last_of("/");
        if (slash_pos != std::string::npos && slash_pos + 1 < prefix.length())
        {
            std::string ip_fullname = prefix;
            std::string ip_name = prefix.substr(0, slash_pos);
            int prefix_length = std::stoi(prefix.substr(slash_pos + 1));

            if (prefix_length > 32)
            {
                // invalid prefix length
                exit_program("Invalid network prefix format: " + prefix);
            }

            // Check for duplicates in the existing vector
            bool duplicate = false;
            for (const auto &info : IP_infos)
            {
                if (info.ip_full_name == ip_fullname) // Check if the IP address is already in the vector
                {
                    duplicate = true; 
                    break;
                }
            }

            if (!duplicate) // If the IP address is not in the vector
            {
                // max hosts for given prefix
                unsigned int max_hosts = calculate_max_hosts(prefix_length);

                // push IPInfo to vector
                IP_infos.push_back(IPInfo(ip_fullname, ip_name, prefix_length, max_hosts, 0, 0.0));
            }
        }
        else
        {
            exit_program("Invalid network prefix format: " + prefix);
        }
    }
    return IP_infos;
}


// calculate max hosts for given prefix
unsigned int calculate_max_hosts(int prefix_length)
{
    unsigned int max_hosts = pow(2, (32 - prefix_length)) - 2;
    return max_hosts;
}

// sort IPInfo by ip_full_name
bool sort_IP_info(const IPInfo &a, const IPInfo &b)
{
    return a.ip_full_name > b.ip_full_name;
}