#include <iostream>
#include <ncurses.h>
#include <syslog.h>

// functions

void log_exceeded_prefix(const std::string &prefix);
void initialize_ncurses();
void cleanup_ncurses();
void exit_program(const std::string &message);
void sigint_handler(int signum);
void print_help();