// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)
// Description: IP info struct and functions

#include "ip_info.h"

// convert vector of strings to vector of IPInfo
std::vector<IPInfo> convert_to_IP_info(const std::vector<std::string> &prefixes)
{
    std::vector<IPInfo> IPInfos;
    for (const std::string &prefix : prefixes)
    {
        size_t slash_pos = prefix.find_last_of("/");
        if (slash_pos != std::string::npos && slash_pos + 1 < prefix.length())
        {
            std::string ip_fullname = prefix;
            std::string ip_name = prefix.substr(0, slash_pos);
            int prefix_length = std::stoi(prefix.substr(slash_pos + 1));

            // max hosts for given prefix
            int max_hosts = calculate_max_hosts(prefix_length);

            // push IPInfo to vector
            IPInfos.push_back(IPInfo(ip_fullname, ip_name, prefix_length, max_hosts, 0, 0.0));
        }
        else
        {
            std::cerr << "Neplatný formát síťového prefixu: " << prefix << std::endl;
        }
    }
    return IPInfos;
}

// calculate max hosts for given prefix
int calculate_max_hosts(int prefix_length)
{
    int max_hosts = pow(2, (32 - prefix_length)) - 2;
    return max_hosts;
}

// sort IPInfo by ip_full_name
bool sort_IP_info(const IPInfo &a, const IPInfo &b)
{
    return a.ip_full_name > b.ip_full_name;
}