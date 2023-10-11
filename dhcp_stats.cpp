#include <iostream>
#include <unistd.h>
#include <vector>
#include "arg_parser.h"
#include "dhcp_monitor.h"


int main(int argc, char *argv[])
{
    initializeNcurses();

    DHCP_monitor(argc, argv);
    // TODO pridat serazeni

    cleanupNcurses();
    return 0;
}
