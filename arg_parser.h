#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <regex>
#include "ncurses_logger.h"
#include <iostream>
#include <string>
#include <vector>
#include <regex>

// Struct for storing arguments
struct arguments
{
    std::string filename;
    std::string interface;
    std::vector<std::string> IP_prefixes;
};
// functions

// func to valid correct format of ip adress
bool is_IPv4_valid(const std::vector<std::string> &ipAddresses);
// main function to parse
struct arguments arg_parse(int argc, char *const *argv);

void validate(struct arguments *args);