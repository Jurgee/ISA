#include <iostream>
#include <unistd.h>
#include <vector>
#include "arg_parser.h"
#include "dhcp_monitor.h"
#include "ip_info.h"

int main(int argc, char *argv[])
{

    DHCP_monitor(argc, argv);
    // TODO pridat serazeni
    return 0;
}
