import argparse
import dns.resolver
import threading
import queue
import requests
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# List of common CNAME keywords indicating potential takeover
TAKEOVER_CNAME_KEYWORDS = [
    "unavailable", "expired", "not found", "does not exist", "missing"
]

# Function to resolve a domain and check for vulnerabilities
def check_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).strip(".")
            print(f"[INFO] {domain} -> CNAME: {cname}")

            # Check for potential takeover strings
            if any(keyword in cname.lower() for keyword in TAKEOVER_CNAME_KEYWORDS):
                print(f"[ALERT] Potential takeover detected for {domain} -> {cname}")

            # Optional: HTTP validation
            try:
                response = requests.get(f"http://{domain}", timeout=5)
                if response.status_code in [404, 410]:
                    print(f"[ALERT] {domain} returns HTTP {response.status_code}")
            except requests.RequestException as e:
                print(f"[ERROR] HTTP validation failed for {domain}: {e}")

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"[WARNING] No CNAME record found for {domain}")
    except Exception as e:
        print(f"[ERROR] Failed to resolve {domain}: {e}")

# Function to generate domains from subnets and IPs
def generate_domains(ip_or_subnet):
    try:
        if "/" in ip_or_subnet:
            # Handle subnet (CIDR notation)
            subnet = ipaddress.ip_network(ip_or_subnet, strict=False)
            return [str(ip) for ip in subnet]
        else:
            # Handle single IP
            return [ip_or_subnet]
    except ValueError:
        print(f"[ERROR] Invalid IP or subnet: {ip_or_subnet}")
        return []

# Worker thread for processing domains
def worker(domain_queue):
    while not domain_queue.empty():
        domain = domain_queue.get()
        try:
            check_domain(domain)
        finally:
            domain_queue.task_done()

def main(input_file, threads):
    domain_queue = queue.Queue()

    # Read IPs and subnets from the file and generate domains
    with open(input_file, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                domains = generate_domains(line)
                for domain in domains:
                    domain_queue.put(domain)

    # Start threads to process domains
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for _ in range(threads):
            executor.submit(worker, domain_queue)

    domain_queue.join()
    print("[INFO] Scan complete!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Zone/Subdomain Takeover Scanner")
    parser.add_argument("-i", "--input", required=True, help="Input file containing IPs or subnets")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    args = parser.parse_args()

    main(args.input, args.threads)
