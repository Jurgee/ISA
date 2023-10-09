#include <iostream>
#include <unistd.h>
#include <vector>
#include "arg_parser.h"
#include "dhcp_monitor.h"
#include "ip_info.h"

int main(int argc, char *argv[])
{

    struct arguments args = Arg_parse(argc, argv);
    DHCP_monitor(args.filename, args.interface);

    std::vector<IPInfo> IPInfos = Convert_to_IP_info(args.ipPrefixes);
    std::cout << "IP-Prefix Max-hosts Allocated addresses Utilization" << std::endl;
    for (const IPInfo &info : IPInfos)
    {
        std::cout << info.ip_name << " " << info.max_hosts << std::endl;
    }

    // TODO pridat serazeni
    return 0;
}
