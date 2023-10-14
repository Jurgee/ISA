// ISA 2023/2024
// Author : Jiří Štípek (xstipe02)
// Description: Main file of the program

#include "dhcp_monitor.h"
#include "ncurses_logger.h"

int main(int argc, char *argv[])
{
    DHCP_monitor(argc, argv);
    cleanup_ncurses();
    return 0;
}
