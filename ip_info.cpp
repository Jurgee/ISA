#include <iostream>
#include <string>
#include <vector>
#include "ip_info.h"
#include <cmath>

std::vector<IPInfo> Convert_to_IP_info(const std::vector<std::string> &prefixes)
{
    std::vector<IPInfo> IPInfos;
    for (const std::string &prefix : prefixes)
    {
        size_t slash_pos = prefix.find_last_of("/");
        if (slash_pos != std::string::npos && slash_pos + 1 < prefix.length())
        {
            std::string ip_name = prefix;
            int prefix_length = std::stoi(prefix.substr(slash_pos + 1));

            // Výpočet max_hosts pro daný síťový prefix
            int max_hosts = calculateMaxHosts(prefix_length);

            // Přidání IPInfo s maximálním počtem hostitelů do výstupního vektoru
            IPInfos.push_back(IPInfo(ip_name, prefix_length, max_hosts, 0, 0.0));
        }
        else
        {
            std::cerr << "Neplatný formát síťového prefixu: " << prefix << std::endl;
        }
    }
    return IPInfos;
}

int calculateMaxHosts(int prefix_length)
{
    int max_hosts = pow(2, (32 - prefix_length)) - 2;
    return max_hosts;
}