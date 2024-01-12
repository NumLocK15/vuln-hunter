"""
Vuln-Hunter: Automated Domain and Host vulneratbility hunting Tool
Version: 0.0.1
Author: NumLocK15 (https://github.com/NumLocK15)
Created: 12/1/2024
Last Modified: notyet

Description:
    Vuln-Hunter is a script designed to automate the process of scanning domains
    and hosts for vulnerabilities and misconfigurations. It integrates tools
    like Nuclei, Katana, Subfinder, and ParamSpider for reconnaissance and 
    vulnerability assessment. This script is not intended to replace thorough
    security assessments. Rather, it is a tool for quickly identifying 
    low-hanging fruit that can be particularly beneficial in large-scale
    engagements and bug bounty activities. Users should follow up with 
    in-depth analysis and testing as needed.

Requirements:
    - Python 3.6+
    - External tools: Nuclei, Katana, Subfinder, ParamSpider, Nuclei Fuzzing tempaltes
    - Relevant Python packages: argparse, concurrent.futures, os, re, tqdm, shutil

Usage:
    python vuln-hunter.py [options]

"""

import subprocess
import argparse
import os
import re
import concurrent.futures
import threading
from tqdm import tqdm
import shutil
from urllib.parse import urlparse, parse_qs


# ASCII Art for Vuln-Hunter
ascii_art = """

██╗   ██╗██╗   ██╗██╗     ███╗   ██╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║   ██║██║   ██║██║     ████╗  ██║      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                                              
"""

# ANSI color codes
GREEN = '\033[92m'
NC = '\033[0m'  # No Color
RED = '\033[91m'

AGGREGATED_RESULTS_FILE = "nuclie_aggregated_result.txt"  # Define a global results file
file_write_lock = threading.Lock()  # Create a global lock for file writing to avoid race condition

print(ascii_art)

# Help message
help_message = """
Vuln-Hunter: Automated Domain and Host Monitoring Tool

This tool is designed to automate the process of scanning domains and hosts for vulnerabilities and misconfigurations. It supports various scanning modes and options to customize your security assessment needs.

Usage:
    python adhm_hunt.py [options]

Options:
    -d, --domain          Specify a single domain for scanning.
    -l, --domain_list     Specify a file containing a list of domains (one per line).
    --fuzzing             Perform Nuclei fuzzing scan.
    --complete            Perform both basic and fuzzing scans.
    --paramspider         Use ParamSpider for parameterized URL discovery. By default, Katana is used.
    --nobasic             Disable Nuclei basic scan.
    -cs, --concurrentscans Specify the number of concurrent scans to run. Default is 2.
    -t, --timeout         Set a timeout for each scan in minutes. Default is 30 minutes.
    --silent              Run scans in silent mode with minimal output.

Installation Instructions:
  nuclei:
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  fuzzing templates:
    git clone https://github.com/projectdiscovery/fuzzing-templates.git
    mv fuzzing-templates /home/adhm/.local/nuclei-templates/
  katana:
    go install github.com/projectdiscovery/katana/cmd/katana@latest
  subfinder:
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  paramspider:
    git clone https://github.com/devanshbatham/paramspider
    cd paramspider
    pip install .
  
  NOTE: Ensure that your Go bin directory is included in your system's PATH. If it's not already set, you can temporarily add it to your PATH with the following command:
  (export PATH=$PATH:$HOME/go/bin)
  This step is necessary to run tools installed via Go directly from the command line.

Examples:
    Scan a single domain with a basic scan:
        python adhm_hunt.py -d example.com

    Scan multiple domains from a file with both basic and fuzzing scans:
        python adhm_hunt.py -l domains.txt --complete

    Run scans in silent mode for a single domain with a timeout of 15 minutes:
        python adhm_hunt.py -d example.com --silent -t 15
"""

def is_valid_domain_or_ip(domain):
    # Regex for validating a domain name
    domain_regex = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # Regex for validating an IPv4 address
    ipv4_regex = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    # Regex for validating an IPv6 address
    ipv6_regex = r'^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$'
    
    # Check if the input is a valid domain or IP address
    return re.match(domain_regex, domain) or re.match(ipv4_regex, domain) or re.match(ipv6_regex, domain)


# Argument parsing
parser = argparse.ArgumentParser(description='Vuln-Hunter: Automated Domain and Host Monitoring Tool\n\n'
                                             'This tool is designed to automate the process of scanning domains '
                                             'and hosts for vulnerabilities and misconfigurations.',
                                 epilog=help_message,
                                 formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-d', '--domain', help='Specify a single domain')
parser.add_argument('-l', '--domain_list', help='Specify a file with a list of domains')
parser.add_argument('--fuzzing', action='store_true', help='Perform nuclie fuzzing scan')
parser.add_argument('--complete', action='store_true', help='Perform both basic and fuzzing scans')
parser.add_argument('--paramspider', action='store_true', help='Use ParamSpider for parameterized URLs, by default Katana is used')
parser.add_argument('--nobasic', action='store_true', default=0,help='disable nuclie basic scan')
parser.add_argument('-cs', '--concurrentscans', type=int, default=2, help='Number of concurrent scans')
parser.add_argument('-t', '--timeout', type=int, default=30, help='Timeout for each scan in minutes')
parser.add_argument('--silent', action='store_true', help='Run scans in silent mode')
parser.add_argument('--techdetect', action='store_true', help='Run a technoligy scan on the target')
parser.add_argument('--allparams', action='store_true', help='using this option will use both katana and paramspider for url extraction then merge them before fuzzing')

def check_prerequisites():
    tools = {
        "katana": "katana --version",
        "paramspider": "paramspider --help",
        "nuclei": "nuclei -version",
        "httpx": "httpx -version",
        "subfinder": "subfinder -version"
    }

    all_installed = True

    for tool, command in tools.items():
        try:
            subprocess.run(command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"Prerequisite check failed: {tool} is not installed or not found in PATH.")
            all_installed = False

    return all_installed

# Example usage
if not check_prerequisites():
    print("Please install all required prerequisites before running this script.")
    exit(1)

args = parser.parse_args()

# Check if either a domain or a domain list is provided
if not args.domain and not args.domain_list:
    parser.print_usage()
    exit(1)

# Define nuclie scan type
scan_type = "basic"
if args.fuzzing:
    scan_type = "fuzzing"
if args.complete:
    scan_type = "complete"

# Define nuclie scan type
silent_mode_temp = 0
if args.silent:
    silent_mode_temp = 1

# Define techdetect
techdetect = 0
if args.techdetect:
    techdetect = 1

# Define allparams for exuting paramspider and katana
all_params = 0
if args.allparams:
    all_params = 1


# Define techdetect
timeout_value = 900
if args.allparams:
    timeout_value = args.timeout * 60

def run_command(command):
    """Helper function to run a command with optional silence and timeout."""
    try:
        if silent_mode_temp:
            subprocess.run(command, timeout_value, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(command, timeout_value)
    except subprocess.TimeoutExpired:
        print(f"{RED}Command timed out: {' '.join(command)}{NC}")

def nuclie_scan (results_dir):
    if not args.nobasic:
        live_domains_file = f"{results_dir}/live-domains"
        nuclei_basic_output_file = f"{results_dir}/nuclei-basic-scan-results"
        nuclei_command = [
            "nuclei", "-l", live_domains_file, "-rl", "500", "-c", "200",
            "-bs", "10", "-timeout", "2", "-severity", "critical,high",
            "-o", nuclei_basic_output_file, "-stats"
        ]
        if silent_mode_temp:
            nuclei_command.append("-silent")
        
        try:
            run_command(nuclei_command)
        except subprocess.TimeoutExpired:
            print(f"{RED}Nuclei basic scan for {results_dir} timed out.{NC}")


        # Thread-safe file append
            
        with file_write_lock:
            with open(AGGREGATED_RESULTS_FILE, "a") as agg_file:
                with open(nuclei_basic_output_file, "r") as basic_results:
                    content = basic_results.read()
                    if content.strip():  # Checks if the content is non-empty after stripping whitespace
                        agg_file.write(content)
                        agg_file.write("\n")  # Add a newline only if there was content

        print(f"{GREEN}Nuclei basic scan completed. Results are available in {nuclei_basic_output_file}.{NC}")
    else:
        print(f"{GREEN} Skipping Basic scan..{NC}")


def normalize_url(url):
    """
    Normalize a URL by removing the protocol (http or https) and 'www.' prefix.
    """
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]

    if url.startswith("www."):
        url = url[4:]

    return url

def read_urls_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]  # Read non-empty lines
    except FileNotFoundError:
        print(f"Warning: File not found - {file_path}")
        return []

def merge_and_deduplicate_urls(katana_file, paramspider_file, output_file):
    # Read URLs from files
    katana_urls = read_urls_from_file(katana_file)
    paramspider_urls = read_urls_from_file(paramspider_file)

    # Normalize URLs
    normalized_katana_urls = [normalize_url(url) for url in katana_urls]
    normalized_paramspider_urls = [normalize_url(url) for url in paramspider_urls]

    # Merge and remove duplicates
    combined_urls = set(normalized_katana_urls + normalized_paramspider_urls)

    # Check if there are any URLs to process
    if not combined_urls:
        print("No URLs to process. Both Katana and ParamSpider files are missing, empty, or contain only empty lines.")
        return

    # Write merged and deduplicated URLs to the output file
    with open(output_file, 'w') as file:
        for url in sorted(combined_urls):
            file.write(url + '\n')


def tech_detect_func (results_dir):
    # Run nuclie tech-detect
    live_domains_file = f"{results_dir}/live-domains"
    tech_domains_file = f"{results_dir}/tech-domains"

    tech_command = [
        "nuclei", "-rl", "500", "-c", "200", "-bs", "10",
        "-timeout", "2", "-retries", "0", "-tags", "tech",
        "-list", live_domains_file, "-o", tech_domains_file, "-stats"
    ]
    run_command(tech_command)
    print(f"{GREEN} Checking Tecknoligy is completed. Results are stored in {results_dir}/tech-domains.{NC}") 

def run_paramspider (live_domains_file, extracted_params_file):
   
    paramspider_command = ["paramspider", "-l", live_domains_file, "-s"]

    run_command(paramspider_command)
    

    # Read the contents of live_domains_file
    with open(live_domains_file, "r") as file:
        domains = file.readlines()
    
    with open(extracted_params_file, "a") as aggregated_file:
        for domain in domains:
            domain = domain.strip()  # Remove newline and any trailing whitespace

            # Remove http:// or https:// prefixes from domain
            cleansed_domain = domain.replace("http://", "").replace("https://", "")
            default_output_file = f"results/{cleansed_domain}.txt"

            if os.path.exists(default_output_file):
                with open(default_output_file, "r") as domain_file:
                    data = domain_file.read()
                    if data:
                        aggregated_file.write(data)
                    else:
                        print(f"Warning: File {default_output_file} is empty.")
            else:
                print(f"Warning: File {default_output_file} does not exist.")
    
    print(f"{GREEN}Parameterized URL search with ParamSpider completed. Results are stored in {extracted_params_file}.{NC}")

def run_katana (live_domains_file, extracted_params_file):
    # Run Katana with output directed to a file

    katana_command = ["katana", "-list", live_domains_file, "-f", "qurl", "-timeout", "2","-aff", "-c", "50", "-p", "50","-ignore-query-params","-strategy", "breadth-first", "-ef","png,css,js", "-o", extracted_params_file]
    katana_command.append("-silent")
    katana_command.append("-ignore-query-params")

    run_command(katana_command)
    print(f"{GREEN}Parameterized URL search with Katana completed. Results are stored in {extracted_params_file}.{NC}")

def extract_params (results_dir,paramspider_arg):
    extracted_params_file = f"{results_dir}/extractedParamResults"
    live_domains_file = f"{results_dir}/live-domains"

    katana_extracted_params_file =  extracted_params_file +"-katana" 
    paramspider_extracted_params_file = extracted_params_file + "-paramspider"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        if all_params:
            # Run both ParamSpider and Katana concurrently
            executor.submit(run_paramspider, live_domains_file, paramspider_extracted_params_file)
            executor.submit(run_katana, live_domains_file, katana_extracted_params_file)
        else:
            # Run either ParamSpider or Katana
            if paramspider_arg:
                executor.submit(run_paramspider, live_domains_file, paramspider_extracted_params_file)
            else:
                executor.submit(run_katana, live_domains_file, katana_extracted_params_file)

    merge_and_deduplicate_urls (katana_extracted_params_file,paramspider_extracted_params_file,extracted_params_file)

def nuclie_fuzzing (results_dir):
        
    extracted_params_file = f"{results_dir}/extractedParamResults"

    # Run nuclei for fuzzing scan
    nuclei_fuzzing_output_file = f"{results_dir}/nuclei-fuzzer-results"
    nuclei_command = [
        "nuclei", "-rl", "500", "-c", "200", "-bs", "10",
        "-timeout", "2", "-retries", "0", "-t", "fuzzing-templates",
        "-list", extracted_params_file, "-o", nuclei_fuzzing_output_file, "-stats"
    ]
    if silent_mode_temp:
        nuclei_command.append("-silent")

    try:
        run_command(nuclei_command)

    except subprocess.TimeoutExpired:
        print(f"{RED}Nuclei fuzzing scan for {results_dir} timed out.{NC}")

    with file_write_lock:
        with open(AGGREGATED_RESULTS_FILE, "a") as agg_file:
            with open(nuclei_fuzzing_output_file, "r") as fuzzing_results:
                content = fuzzing_results.read()
                if content.strip():  # Checks if the content is non-empty after stripping whitespace
                    agg_file.write(content)
                    agg_file.write("\n")  # Add a newline only if there was content

    print(f"{GREEN}Nuclei fuzzing scan completed. Results are available in {nuclei_fuzzing_output_file}.{NC}")

# Perform scan
def perform_scan(scan_domain, scan_type, paramspider_arg):
    #### Validate the domain before starting
    if not is_valid_domain_or_ip(scan_domain):
        print(f"Invalid domain format: {scan_domain}")
        return

    #### create the results folder
    results_dir = f"Results:{scan_domain}"
    os.makedirs(results_dir, exist_ok=True)
    print(f"Directory '{results_dir}' created for storing results.")

    #### Starting the enumeration process
    # Run subfinder
    subfinder_command = ["subfinder", "-d", scan_domain, "-o", f"{results_dir}/all-domains"]
    if silent_mode_temp:
        subfinder_command.append("-silent")
    run_command(subfinder_command)
    print(f"{GREEN}subdomain search with subfinder is completed. Results are stored in {results_dir}/all-domains.{NC}")


    # Run httpx
    httpx_command = ["httpx", "-l", f"{results_dir}/all-domains", "-o", f"{results_dir}/live-domains"]
    if silent_mode_temp:
        httpx_command.append("-silent")

    run_command(httpx_command)
    print(f"{GREEN}live cheack with httpx is completed. Results are stored in {results_dir}/live-domains.{NC}")



    #### starting the scanning process
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        live_domains =f"{results_dir}/live-domains"
        if scan_type in ["basic", "complete"]:
            futures.append(executor.submit(nuclie_scan, results_dir))
        if scan_type in ["fuzzing", "complete"]:
            extract_params (results_dir,paramspider_arg)
            futures.append(executor.submit(nuclie_fuzzing, results_dir))
        if techdetect:
            futures.append(executor.submit(tech_detect_func, results_dir))

        # Wait for all futures to complete
        for future in concurrent.futures.as_completed(futures):
            future.result()  # This will re-raise any exception raised in the thread

# Perform scans based on arguments
if args.domain:
    perform_scan(args.domain, scan_type, args.paramspider)
elif args.domain_list:
    with open(args.domain_list, 'r') as file:
        domains = [line.strip() for line in file if line.strip()]

    # Use ThreadPoolExecutor with user-specified max_workers
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrentscans) as executor:
        # Initialize tqdm progress bar for domain-level progress
        with tqdm(total=len(domains), desc="Total Domains Processed", ncols=100, colour='yellow') as pbar:
            futures = {executor.submit(perform_scan, domain, scan_type, args.paramspider): domain for domain in domains}
            
            for future in concurrent.futures.as_completed(futures):
                domain = futures[future]
                try:
                    future.result()  # This will re-raise any exception raised in the thread
                except Exception as e:
                    print(f"Error processing domain {domain}: {e}")
                finally:
                    pbar.update(1)  # Update progress bar for each completed domain
