#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <regex>


struct arguments{
std::string filename;
std::string interface;
std::vector<std::string> ipPrefixes;
};

//func to valid correct format of ip adress
bool is_IPv4_valid(const std::vector<std::string>& ipAddresses);

// main function to parse 
struct arguments Arg_parse(int argc, char *const *argv);


const std::vector<std::string>& get_IP_prefixes(); 

void print_help();
void validate(struct arguments *args);