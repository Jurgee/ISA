#include "ncurses_logger.h"

// Log the given prefix to syslog
void log_exceeded_prefix(const std::string &prefix)
{
    std::string logMessage = "prefix " + prefix + " exceeded 50% of allocations.";
    syslog(LOG_NOTICE, "%s", logMessage.c_str());

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