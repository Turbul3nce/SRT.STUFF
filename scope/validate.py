#!/usr/bin/env python3
# Script to check if we are within scope

import ipaddress
import sys

def is_ip_in_scope(ip, cidr_ranges):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in cidr_ranges:
            if ip_obj in ipaddress.ip_network(cidr.strip()):
                return True
        return False
    except ValueError as e:
        print(f"Invalid IP or CIDR: {e}")
        return False

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 scope_checker.py <ip_address> <scope_file>")
        sys.exit(1)

    ip_address = sys.argv[1]
    scope_file = sys.argv[2]

    try:
        with open(scope_file, 'r') as f:
            cidr_ranges = f.readlines()

        if is_ip_in_scope(ip_address, cidr_ranges):
            print(f"{ip_address} is within the scope.")
        else:
            print(f"{ip_address} is NOT within the scope.")
    
    except FileNotFoundError:
        print(f"Scope file {scope_file} not found.")
        sys.exit(1)

if __name__ == "__main__":
    main()
