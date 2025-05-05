# Web Scanner

An advanced web scanning tool designed to perform a series of reconnaissance operations on a target domain. It includes features such as subdomain resolution, directory enumeration, meta-data extraction, HTTP header analysis, keyword scanning, and more.

## Features

- **IP Resolution**: Resolves the domain to an IP address.
- **robots.txt Check**: Checks for the existence of a `robots.txt` file and analyzes any disallowed paths.
- **Directory Enumeration**: Scans an URL for common directories.
- **Crawling**: Crawls the website to a defined depth, collecting all discovered links.
- **Data Extraction**: Extracts and logs meta-data, scripts, and iframes from the page.
- **Keyword Scanner**: Scans a webpage for specific keywords.
- **HTTP Header Analysis**: Analyzes the HTTP headers of a webpage.
- **Subdomain Enumeration**: Scans for subdomains of a domain using a wordlist.
- **Advanced Scanning with Threading**: Uses multithreading to perform fast directory and path scans.
- **WHOIS Lookup**: Retrieves WHOIS data for a domain.
- **Port Scanner**: Scans IP ports to identify open ones.

## Requirements

- Python 3.x
- Necessary Python modules:
    - `requests`
    - `beautifulsoup4`
    - `whois`
    - `socket`
    - `threading`
    - `queue`
    - `re`
    - `json`

You can install the required modules via pip:

```bash
pip install requests beautifulsoup4 python-whois

## Usage

Run the script with the following arguments:
```bash
python scanner.py <url> <wordlist> <subdomains>

•	url: The target URL to scan.

•	wordlist: The path to the file containing a list of directories or paths to search.

•	subdomains: The path to the file containing a list of subdomains to enumerate.

## EXAMPLE

```python scanner.py http://example.com wordlist.txt subdomains.txt```

## Module Description
•	scanner.py: This is the main module that performs the domain scanning. It uses various functions to gather information, such as DNS resolution, content analysis, directory scanning, and more.

Main Functions
•	log(msg): A logging function that prints status messages.

•	save_results(filename=“results.txt”): Saves the scanning results to a text file.

•	check_robots_txt(url): Checks the website’s robots.txt file for restrictions.

•	enumerate_directories(url, wordlist): Performs directory enumeration on a URL using a wordlist of paths.

•	resolve_ip(domain): Resolves the domain to an IP address and returns the associated host.

•	crawl(url, depth=2): Crawls a website up to a certain depth, collecting all discovered links.

•	extract_page_data(url): Extracts meta-data, scripts, and iframes from a webpage.

•	scan_keywords(url, wordlist): Scans a page for specific keywords.

•	analyze_headers(url): Analyzes the HTTP headers of a webpage.

•	subdomain_enum(domain, wordlist): Performs subdomain enumeration of a domain using a wordlist.

•	threaded_worker_scan(): A multithreading function used in advanced scanning.

•	advanced_scan(base_url, paths_file): Performs an advanced scan using threading to check the paths of a website.

•	whois_lookup(domain): Retrieves and logs WHOIS data for a domain.

•	port_scan(ip): Scans the ports of an IP address to identify open ports.

## Execution

Once the program is run, the results are printed to the console and saved in the results.txt file. Each function logs useful information during the scan.

### Disclaimer

This tool is intended for educational purposes and ethical use only. It is designed for penetration testing and security research within authorized environments. You must have explicit permission to scan and test the security of any system, website, or network.

Using this tool on websites or systems without permission may be illegal and could result in legal consequences. The author of this tool is not responsible for any misuse or damage caused by its use.

Always ensure that your activities comply with local laws and regulations. Use responsibly.
