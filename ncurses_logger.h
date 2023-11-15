// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)

#ifndef NCURSES_LOGGER
#define NCURSES_LOGGER

#include <iostream>
#include <ncurses.h>
#include <syslog.h>
#include <set>

// functions

void log_exceeded_prefix(const std::string &prefix);
void initialize_ncurses();
void cleanup_ncurses();
void exit_program(const std::string &message);
void print_help();

#endif // NCURSES_LOGGER