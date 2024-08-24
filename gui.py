import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import socket
import whois
import dns.resolver
import httpx
import ssl
import requests
import ipwhois
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Function Definitions
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
            output = subprocess.run(["ping", "-c", str(count), ip], capture_output=True, text=True, check=True)
            return output.stdout
        except subprocess.CalledProcessError as e:
            return f"Error: {str(e)}"
    else:
        return "Error: ping command not available"

def run_domain_check(domain):
    if not domain.startswith(("http://", "https://")):
        domain = "http://" + domain

    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, f"WHOIS: {get_whois(domain)}\n")
    output_text.insert(tk.END, f"DNS Records: {get_dns_records(domain)}\n")
    output_text.insert(tk.END, f"SSL Certificate: {get_ssl_certificate(domain)}\n")
    output_text.insert(tk.END, f"DNSSEC Validation: {check_dnssec(domain)}\n")
    output_text.insert(tk.END, f"SPF And DMARC Records: {get_email_security_records(domain)}\n")
    output_text.insert(tk.END, f"Website Content Preview: {check_website_content(domain)}\n")
    output_text.insert(tk.END, f"Website Performance: {measure_website_performance(domain)}\n")

def run_ip_check(ip, port):
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, f"Reverse DNS: {get_reverse_dns(ip)}\n")
    output_text.insert(tk.END, f"Geolocation: {get_ip_geolocation(ip)}\n")
    output_text.insert(tk.END, f"Open Ports: {scan_open_ports(ip)}\n")
    output_text.insert(tk.END, f"WHOIS Information: {get_whois_info(ip)}\n")
    output_text.insert(tk.END, f"SSL Certificate Information: {get_ssl_certificate(ip, port)}\n")
    output_text.insert(tk.END, f"Banner: {grab_banner(ip, port)}\n")
    output_text.insert(tk.END, f"Latency Ping: {ping_latency(ip)}\n")

def save_report():
    report = output_text.get(1.0, tk.END)
    if not report.strip():
        messagebox.showwarning("No Content", "No content to save.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(report)
            file.write("\n\n--- Report Generated ---\n")
            file.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        messagebox.showinfo("Report Saved", "Report saved successfully!")

def example_domain(domain):
    domain_entry.delete(0, tk.END)
    domain_entry.insert(0, domain)
    run_domain_check(domain)

# Create the GUI
root = tk.Tk()
root.title("Domain and IP Analyzer")
root.configure(bg='#1E90FF')

# Domain Section
domain_frame = tk.LabelFrame(root, text="Domain Check", bg='#1E90FF', fg='white', padx=10, pady=10)
domain_frame.pack(padx=10, pady=10, fill="both", expand="yes")

domain_label = tk.Label(domain_frame, text="Enter Domain:", bg='#1E90FF', fg='white')
domain_label.grid(row=0, column=0, pady=5)

domain_entry = tk.Entry(domain_frame, width=40)
domain_entry.grid(row=0, column=1, pady=5)

check_domain_btn = tk.Button(domain_frame, text="Check Domain", command=lambda: run_domain_check(domain_entry.get()), bg='#4682B4', fg='white')
check_domain_btn.grid(row=0, column=2, padx=10)

# Example Domains Buttons
example_frame = tk.Frame(domain_frame, bg='#1E90FF')
example_frame.grid(row=1, columnspan=3, pady=10)

google_btn = tk.Button(example_frame, text="Google.com", command=lambda: example_domain("google.com"), bg='#4682B4', fg='white')
google_btn.pack(side=tk.LEFT, padx=5)

example_btn = tk.Button(example_frame, text="Example.com", command=lambda: example_domain("example.com"), bg='#4682B4', fg='white')
example_btn.pack(side=tk.LEFT, padx=5)

github_btn = tk.Button(example_frame, text="GitHub.com", command=lambda: example_domain("github.com"), bg='#4682B4', fg='white')
github_btn.pack(side=tk.LEFT, padx=5)

# IP and Port Section
ip_frame = tk.LabelFrame(root, text="IP + Port Check", bg='#1E90FF', fg='white', padx=10, pady=10)
ip_frame.pack(padx=10, pady=10, fill="both", expand="yes")

ip_label = tk.Label(ip_frame, text="Enter IP:", bg='#1E90FF', fg='white')
ip_label.grid(row=0, column=0, pady=5)

ip_entry = tk.Entry(ip_frame, width=30)
ip_entry.grid(row=0, column=1, pady=5)

port_label = tk.Label(ip_frame, text="Enter Port:", bg='#1E90FF', fg='white')
port_label.grid(row=0, column=2, pady=5)

port_entry = tk.Entry(ip_frame, width=10)
port_entry.grid(row=0, column=3, pady=5)

check_ip_btn = tk.Button(ip_frame, text="Check IP + Port", command=lambda: run_ip_check(ip_entry.get(), int(port_entry.get())), bg='#4682B4', fg='white')
check_ip_btn.grid(row=0, column=4, padx=10)

# Output Section
output_frame = tk.LabelFrame(root, text="Output", bg='#1E90FF', fg='white', padx=10, pady=10)
output_frame.pack(padx=10, pady=10, fill="both", expand="yes")

output_text = scrolledtext.ScrolledText(output_frame, width=80, height=20, wrap=tk.WORD)
output_text.pack()

# Save Report Button
save_btn = tk.Button(root, text="Save Report", command=save_report, bg='#4682B4', fg='white')
save_btn.pack(pady=10)

root.mainloop()
