// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)
// Description: Logger and ncurses functions

#include "ncurses_logger.h"

// set for storing prefixes that exceeded 50% of allocated addresses
std::set<std::string> exceeded_prefixes;

// if we have more than 50% of IP addresses allocated, log it
void log_exceeded_prefix(const std::string &prefix)
{
    if (exceeded_prefixes.find(prefix) == exceeded_prefixes.end()) // is not in set
    {
        // Log to syslog
        syslog(LOG_NOTICE, "prefix %s exceeded 50%% of allocations.\n", prefix.c_str());

        // Add the prefix to the set of exceeded prefixes
        exceeded_prefixes.insert(prefix);
    }
    // Display in the ncurses window
    printw("prefix %s exceeded 50%% of allocations.\n", prefix.c_str());
    refresh();
}

// Initialize ncurses
void initialize_ncurses()
{
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    mvprintw(0, 0, "IP-Prefix Max-hosts Allocated addresses Utilization\n"); // Print the header
    refresh();
}

// Cleanup ncurses
void cleanup_ncurses()
{
    endwin();
}

// Exit the program with the given message to stderr
void exit_program(const std::string &message)
{
    std::cerr << message << std::endl;
    exit(1);
}

// print help
void print_help()
{
    std::cerr << "./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ] \n \
            -r <filename> - statistika bude vytvořena z pcap souborů \n \
            -i <interface> - rozhraní, na kterém může program naslouchat \n \
            <ip-prefix> - rozsah sítě pro které se bude generovat statistika "
              << std::endl;
}
