// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)
// Description: Logger and ncurses functions

#include "ncurses_logger.h"

// if we have more than 50% of IP addresses allocated, log it
void log_exceeded_prefix(const std::string &prefix)
{
    // Log to syslog
    syslog(LOG_NOTICE, "prefix %s exceeded 50%% of allocations.\n", prefix.c_str());

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
    refresh();
}

// Cleanup ncurses
void cleanup_ncurses()
{
    endwin();
}

// Exit the program with the given message
void exit_program(const std::string &message)
{
    fprintf(stderr, "%s \n", message.c_str());
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
