#include <iostream>
#include <string>
#include <vector>

struct IPInfo {
    std::string ip_name;          
    int prefix;            
    int max_hosts;                
    int allocated_addresses;      
    double utilization;           
    
    IPInfo(const std::string& name, const int& p, int max, int allocated, double util)
        : ip_name(name), prefix(p), max_hosts(max), allocated_addresses(allocated), utilization(util) {}
};


std::vector<IPInfo> Convert_to_IP_info(const std::vector<std::string>& prefixes);
int calculateMaxHosts(int prefix_length);
