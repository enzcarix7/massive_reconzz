from os import mkdir, path
from sys import argv, exit
from urllib.parse import urljoin, urlparse
from socket import gethostbyname, gethostbyaddr, socket, AF_INET, SOCK_STREAM
from datetime import datetime
from threading import Thread, Lock
from queue import Queue
from requests import get, head, RequestException
from re import search, findall
from time import sleep
from bs4 import BeautifulSoup
from json import dumps
from http.client import HTTPConnection

# GLOBAL VARIABLES
output_lock: Lock = Lock()
thread_count: int = 30
queue: Queue = Queue()
results: list = []

# LOGGER
def log(msg: str) -> None:
    with output_lock:
        print(f"[+] {msg}")

# SAVE RESULTS TO FILE
def save_results(filename: str = "results.txt") -> None:
    with open(filename, 'w') as f:
        for line in results:
            f.write(f"{line}\n")

# CHECK ROBOTS.TXT
def check_robots_txt(url: str) -> None:
    try:
        robots_url: str = urljoin(url, '/robots.txt')
        response = get(robots_url, timeout=5)
        if response.status_code == 200:
            log("robots.txt found")
            results.append(robots_url)
            lines: list = response.text.split('\n')
            for line in lines:
                if 'Disallow' in line:
                    log(f"robots.txt Disallow: {line}")
    except Exception as e:
        log(f"robots.txt not found: {e}")

# DIRECTORY ENUMERATION
def enumerate_directories(url: str, wordlist: str) -> None:
    log("Starting directory enumeration...")
    with open(wordlist, 'r') as file:
        for line in file:
            word: str = line.strip()
            full_url: str = urljoin(url, word)
            try:
                response = head(full_url, timeout=5)
                if response.status_code < 400:
                    log(f"Found: {full_url} [{response.status_code}]")
                    results.append(full_url)
            except RequestException:
                pass

# IP RESOLUTION
def resolve_ip(domain: str) -> str:
    try:
        ip: str = gethostbyname(domain)
        host: str = gethostbyaddr(ip)[0]
        log(f"Resolved {domain} to {ip} ({host})")
        return ip
    except Exception as e:
        log(f"Error resolving IP: {e}")
        return ""

# BASIC CRAWLER
def crawl(url: str, depth: int = 2) -> None:
    visited: set = set()

    def _crawl(current_url: str, current_depth: int) -> None:
        if current_depth == 0 or current_url in visited:
            return
        visited.add(current_url)
        try:
            response = get(current_url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href: str = urljoin(current_url, link['href'])
                log(f"Found link: {href}")
                results.append(href)
                _crawl(href, current_depth - 1)
        except Exception:
            pass

    _crawl(url, depth)

# EXTRACT META, SCRIPTS, IFRAMES
def extract_page_data(url: str) -> None:
    try:
        response = get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        metas = soup.find_all('meta')
        for meta in metas:
            log(f"Meta: {meta}")
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src')
            if src:
                log(f"Script: {urljoin(url, src)}")
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            src = iframe.get('src')
            if src:
                log(f"Iframe: {urljoin(url, src)}")
    except Exception as e:
        log(f"Failed to extract data from {url}: {e}")

# KEYWORD SCANNER
def scan_keywords(url: str, wordlist: str) -> None:
    try:
        response = get(url, timeout=5)
        text: str = response.text.lower()
        with open(wordlist, 'r') as file:
            for line in file:
                keyword: str = line.strip().lower()
                if keyword in text:
                    log(f"Keyword found: {keyword} in {url}")
    except Exception as e:
        log(f"Failed to scan {url}: {e}")

# HEADER ANALYSIS
def analyze_headers(url: str) -> None:
    try:
        response = head(url, timeout=5)
        for k, v in response.headers.items():
            log(f"Header: {k}: {v}")
    except Exception as e:
        log(f"Header analysis failed for {url}: {e}")

# SUBDOMAIN ENUMERATION
def subdomain_enum(domain: str, wordlist: str) -> None:
    log("Starting subdomain enumeration...")
    with open(wordlist, 'r') as file:
        for line in file:
            sub: str = line.strip()
            full_domain: str = f"{sub}.{domain}"
            try:
                ip: str = gethostbyname(full_domain)
                log(f"Subdomain found: {full_domain} [{ip}]")
                results.append(full_domain)
            except:
                pass

# MULTI-THREAD SCANNER
def threaded_worker_scan() -> None:
    while not queue.empty():
        url: str = queue.get()
        try:
            response = get(url, timeout=3)
            if response.status_code == 200:
                log(f"Active URL: {url}")
        except Exception:
            pass
        queue.task_done()

# ADVANCED SCAN
def advanced_scan(base_url: str, paths_file: str) -> None:
    log("Starting advanced scan with threading...")
    with open(paths_file, 'r') as f:
        for path_line in f:
            full_url: str = urljoin(base_url, path_line.strip())
            queue.put(full_url)
    for _ in range(thread_count):
        t = Thread(target=threaded_worker_scan)
        t.daemon = True
        t.start()
    queue.join()

# WHOIS LOOKUP
def whois_lookup(domain: str) -> None:
    try:
        from whois import whois
        result = whois(domain)
        log(f"WHOIS data for {domain}: {result}")
    except Exception as e:
        log(f"WHOIS lookup failed: {e}")

# PORT SCANNER
def port_scan(ip: str) -> list:
    open_ports: list = []
    for port in range(1, 1025):
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((ip, port))
            log(f"Port open: {port}")
            open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

# MAIN
def main() -> None:
    if len(argv) < 4:
        print("Usage: python scanner.py <url> <wordlist> <subdomains>")
        exit(1)

    target: str = argv[1]
    wordlist_path: str = argv[2]
    subdomain_wordlist: str = argv[3]

    start: datetime = datetime.now()

    parsed = urlparse(target)
    domain: str = parsed.netloc

    ip: str = resolve_ip(domain)

    check_robots_txt(target)
    crawl(target)
    enumerate_directories(target, wordlist_path)
    scan_keywords(target, wordlist_path)
    analyze_headers(target)
    extract_page_data(target)
    advanced_scan(target, wordlist_path)
    subdomain_enum(domain, subdomain_wordlist)
    whois_lookup(domain)
    if ip:
        port_scan(ip)

    save_results()

    duration = datetime.now() - start
    log(f"Scan complete in {duration}")

if __name__ == "__main__":
    main()
