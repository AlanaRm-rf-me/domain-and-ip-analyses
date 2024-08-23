import socket
import whois
import dns.resolver
import httpx
import ssl
import requests
import ipwhois
import subprocess
import shutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_whois(domain):
    try:
        return whois.whois(domain)
    except Exception as e:
        return str(e)


def get_dns_records(domain):
    records = {}
    for record_type in ['A', 'MX', 'TXT', 'NS', 'SOA']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(r) for r in answers]
        except Exception as e:
            records[record_type] = str(e)
    return records


def get_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": cert.get("issuer"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter")
                }
    except Exception as e:
        return str(e)


def check_dnssec(domain):
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        return True if answers else False
    except Exception as e:
        return str(e)


def get_email_security_records(domain):
    records = {}
    for record_type in ['SPF', 'DMARC']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(r) for r in answers]
        except Exception as e:
            records[record_type] = str(e)
    return records


def check_website_content(domain):
    try:
        response = requests.get(f"http://{domain}")
        return response.text[:1000]
    except requests.RequestException as e:
        return str(e)


def measure_website_performance(domain):
    try:
        response = requests.get(f"http://{domain}")
        timing = response.elapsed.total_seconds()
        return {'load_time_seconds': timing}
    except requests.RequestException as e:
        return str(e)


domain = "example.com"
print("WHOIS:", get_whois(domain))
print("DNS Records:", get_dns_records(domain))
print("SSL Certificate:", get_ssl_certificate(domain))
print("DNSSEC Validation:", check_dnssec(domain))
print("SPF And DMARC Records:", get_email_security_records(domain))
print("Website Content Preview:", check_website_content(domain))
print("Website Performance:", measure_website_performance(domain))


def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)
    except socket.herror:
        return None


def get_ip_geolocation(ip):
    try:
        response = httpx.get(f"https://ipinfo.io/{ip}/json")
        return response.json()
    except Exception as e:
        return str(e)


def check_port(ip, port, timeout=1):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) == 0:
            return port
    return None


def scan_open_ports(ip, ports_range=100, max_threads=50):
    ports = range(1, ports_range + 1)
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_port, ip, port) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports


def get_whois_info(ip):
    try:
        obj = ipwhois.IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        return results
    except Exception as e:
        return str(e)


def get_ssl_certificate(ip, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port)) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return str(e)


def grab_banner(ip, port, timeout=2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        banner = s.recv(1024)
        s.close()
        return banner.decode().strip()
    except Exception as e:
        return str(e)


def ping_latency(ip, count=4):
    if shutil.which("ping"):
        try:
            output = subprocess.run(
                ["ping", "-c", str(count), ip], capture_output=True, text=True, check=True)
            return output.stdout
        except subprocess.CalledProcessError as e:
            return f"Error: {str(e)}"
    else:
        return "Error: ping command not available"


ip = "8.8.8.8"
port = 80
print("Reverse DNS:", get_reverse_dns(ip))
print("Geolocation:", get_ip_geolocation(ip))
print("Open Ports:", scan_open_ports(ip))
print("WHOIS Information:", get_whois_info(ip))
print("SSL Certificate Information:", get_ssl_certificate(ip))
print("Banner:", grab_banner(ip, port))
print("Latency Ping:", ping_latency(ip))
