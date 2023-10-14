#include <iostream>
#include <string>
#include <vector>
#include <cmath>

// Struct for storing IP info
struct IPInfo
{
    std::string ip_full_name;
    std::string ip_name;
    int prefix;
    int max_hosts;
    int allocated_addresses;
    double utilization;

    IPInfo(const std::string &fullname, const std::string &name, const int &p, int max, int allocated, double util)
        : ip_full_name(fullname), ip_name(name), prefix(p), max_hosts(max), allocated_addresses(allocated), utilization(util) {}
};

//functions
std::vector<IPInfo> convert_to_IP_info(const std::vector<std::string> &prefixes);
int calculate_max_hosts(int prefix_length);
bool sort_IP_info(const IPInfo &a, const IPInfo &b);
