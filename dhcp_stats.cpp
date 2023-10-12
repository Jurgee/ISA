#include <iostream>
#include <unistd.h>
#include <vector>
#include "arg_parser.h"
#include "dhcp_monitor.h"
#include "ncurses_logger.h"

int main(int argc, char *argv[])
{
    initialize_ncurses();

    DHCP_monitor(argc, argv);

    cleanup_ncurses();
    return 0;
}
