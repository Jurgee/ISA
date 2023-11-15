// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)

#ifndef IP_INFO
#define IP_INFO

#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include "ncurses_logger.h"
// Struct for storing IP info
struct IPInfo
{
    std::string ip_full_name;
    std::string ip_name;
    int prefix;
    unsigned int max_hosts;
    unsigned int allocated_addresses;
    double utilization;

    IPInfo(const std::string &fullname, const std::string &name, const int &p, unsigned int max, unsigned int allocated, double util)
        : ip_full_name(fullname), ip_name(name), prefix(p), max_hosts(max), allocated_addresses(allocated), utilization(util) {}
};

// functions
std::vector<IPInfo> convert_to_IP_info(const std::vector<std::string> &prefixes);
unsigned int calculate_max_hosts(int prefix_length);
bool sort_IP_info(const IPInfo &a, const IPInfo &b);

#endif // IP_INFO