// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)
// Description: Logger and ncurses functions

#include "ncurses_logger.h"

// Log the given prefix to syslog
void log_exceeded_prefix(const std::string &prefix)
{
    std::string log_message = "prefix " + prefix + " exceeded 50% of allocations.";
    syslog(LOG_NOTICE, "%s", log_message.c_str());

    std::cout << "prefix %s exceeded 50% of allocations." << prefix << std::endl;
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

// signal handler for SIGINT
void sigint_handler(int signum)
{
    (void)signum;
    cleanup_ncurses();
    closelog();
    exit(0);
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
