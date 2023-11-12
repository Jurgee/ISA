# ISA project 2023/2024
## DHCP monitoring tool for network prefix utilization
### Author: Jiří Štípek
### Login: xstipe02
### Date: 09.10.2023

## Description
This tool focuses on monitoring DHCP traffic and collecting statistics on the utilization of a network prefix based on assigned IP addresses. If the network prefix utilization exceeds 50%, the tool notifies the administrator through standard output and logs the event via a syslog server. This project enables the monitoring of IP address availability in the network and facilitates a prompt response to potential issues.

## Limitations
The tool is limited to IPv4 addresses only. Tunneling is not supported. Both interface and filename work with ncurses library.
To exit the program, the user has to press Ctrl+C for the signal.

## Usage
For usage there is `print_help()` function which prints help message. 

Example of usage with filename:
```
./dhcp-stats -r dhcp.pcapng 192.168.1.0/24 192.168.0.0/22
```
Output:
```
IP-Prefix Max-hosts Allocated addresses Utilization
192.168.1.0/24 254 0 0.00%
192.168.0.0/22 1022 1 0.10%
```

## List of files
- dhcp_stats.cpp - main file

- arg_parser.cpp - file for parsing arguments
- arg_parser.h - header file for arg_parser.cpp

- dhcp_monitor.cpp - file for monitoring DHCP traffic
- dhcp_monitor.h - header file for dhcp_monitor.cpp

- ip_info.cpp - file for storing information about IP addresses
- ip_info.h - header file for ip_info.cpp

- ncurses_logger.cpp - file for functions which are used for ncurses library and help/exit functions
- ncurses_logger.h - header file for ncurses_logger.cpp

- Makefile - makefile for compilation
- README.md - readme file
- manual.pdf - manual for this project

