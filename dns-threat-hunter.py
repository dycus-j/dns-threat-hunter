import csv
import re
import time
import logging
import itertools
import concurrent.futures
from collections import Counter
from pathlib import Path
from typing import Dict, List, Iterator, Tuple

# Configure basic logging for debugging and runtime info
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# ==========================================
# 1. CONFIGURATION & THREAT INTELLIGENCE
# ==========================================
THREAT_INTEL = {
    "keywords": {'proxy', 'unblock', 'bypass', 'games', 'mathway', 'math', 'study', 'free'},
    "cloud_hosts": {
        'vercel.app', 'netlify.app', 'onrender.com', 'herokuapp.com', 
        'github.io', 'replit.dev', 'repl.co', 'firebaseapp.com', 'web.app', 'it.com'
    },
    "suspicious_tlds": {'.xyz', '.top', '.site', '.pw', '.cc', '.tk', '.ml'},
    "whitelist_domains": {
        'apple.com', 'icloud.com', 'aaplimg.com', 'akadns.net', 'safebrowsing.apple', 'cdn-apple.com', 'apple-dns.net', # Apple Ecosystem
        'microsoft.com', 'office.com', 'office.net', 'azure.com', 'sharepoint.com', 'msedge.net', 'azurefd.net', 'spo-msedge.net', 'ax-msedge.net', 's-msedge.net', 't-msedge.net', 'dual-s-msedge.net', 'ax-dc-msedge.net', 'dual-s-dc-msedge.net', 'azureedge.net', 'ln-msedge.net', 'ln-dc-msedge.net', # Microsoft Ecosystem
        'google.com', 'firebaseio.com', 'googleusercontent.com', # Google Ecosystem
        'trafficmanager.net', 'cloudfront.net', 'ssl-images-amazon.com', 'akamai.net', 'akamaized.net', 'akamaiedge.net', 'amazonaws.com', 'fastly-edge.com', 'fastly.net', 'ccgateway.net', 'sc-gw.com', 'ibyteimg.com', 'capcutcdn-us.com', 'capcutapi.us', # Major CDNs, AWS, & App Gateways
        'playwire.com', 'intergient.com', 'getepic.com', 'duolingo.com', 'prodigygame.com', 'savvasrealize.com', 'id5-sync.com', 'eu-1-id5-sync.com', 'wixmp.com', 'youversionapi.com', 'sharethrough.com', 'grafana.net', 'intellimizeio.com', # Ad/Tracker & Edu networks
        'arpa' # Local reverse DNS noise
    }
}

CHUNK_SIZE = 10000 

# ==========================================
# 2. VENDOR DATA NORMALIZATION
# ==========================================
def extract_standard_fields(row: Dict[str, str]) -> Tuple[str, str]:
    """
    Normalizes log structures from different vendors (Mosyle, Cisco, Pi-Hole, etc.)
    Returns a standardized tuple: (domain, action)
    """
    domain_keys = ['domain', 'url', 'destination', 'query']
    action_keys = ['action', 'status', 'policy', 'result']
    
    domain = ""
    action = ""

    for key in domain_keys:
        if key in row:
            domain = row[key].strip().lower()
            break
            
    for key in action_keys:
        if key in row:
            action = row[key].strip().upper()
            break
            
    return domain, action

# ==========================================
# 3. THREAT DETECTION ENGINE
# ==========================================
def detect_domain_risks(domain: str) -> List[str]:
    """Analyzes a domain against static risk vectors ONLY (Fast execution)."""
    
    # --- 1. WHITELIST CHECK ---
    # Strict matching to prevent badapple.com from matching apple.com
    if any(domain == wl or domain.endswith('.' + wl) for wl in THREAT_INTEL["whitelist_domains"]):
        return []

    risks = []

    # --- 2. STATIC HEURISTICS ---
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        risks.append("Direct IP Access")
        
    # Strict matching to prevent snapkit.com from matching it.com
    if any(domain == host or domain.endswith('.' + host) for host in THREAT_INTEL["cloud_hosts"]):
        risks.append("Free Cloud/Dev Host")
        
    if any(word in domain for word in THREAT_INTEL["keywords"]):
        risks.append("Suspicious Keyword")
        
    if any(domain.endswith(tld) for tld in THREAT_INTEL["suspicious_tlds"]):
        risks.append("Risky TLD")
        
    if domain.count('-') > 2 or sum(c.isdigit() for c in domain) > 5:
        risks.append("High Entropy (Auto-generated)")

    return risks

# ==========================================
# 4. WORKER FUNCTION (Runs in Parallel)
# ==========================================
def process_chunk(chunk: List[Dict[str, str]]) -> Tuple[int, int, int, Dict[str, List[str]], Counter]:
    """Processes a specific chunk of rows across multiple CPU cores."""
    local_total = 0
    local_blocked = 0
    local_allowed = 0
    local_flagged: Dict[str, List[str]] = {}
    local_counts = Counter()

    for row in chunk:
        local_total += 1
        
        domain, action = extract_standard_fields(row)

        if not domain or not action:
            continue

        # Expanded vocabulary to catch all vendor variations of blocked traffic
        if action in ('BLOCK', 'BLOCKED', 'DENY', 'DENIED', 'DROP', 'DROPPED', 'REJECT', 'REJECTED', 'PREVENT', 'PREVENTED'):
            local_blocked += 1
            
        # Expanded vocabulary to catch all vendor variations of allowed traffic
        elif action in ('ALLOW', 'ALLOWED', 'PASS', 'PASSED', 'PERMIT', 'PERMITTED', 'SUCCESS'):
            local_allowed += 1
            
            risks = detect_domain_risks(domain)
            
            if risks:
                local_counts[domain] += 1
                if domain not in local_flagged:
                    local_flagged[domain] = risks

    return local_total, local_blocked, local_allowed, local_flagged, local_counts

# ==========================================
# 5. DATA INGESTION & CHUNKING
# ==========================================
def yield_chunks(file_path: Path, chunk_size: int) -> Iterator[List[Dict[str, str]]]:
    """Reads the CSV sequentially but yields it in large chunks."""
    if not file_path.exists():
        raise FileNotFoundError(f"Missing file: {file_path}")

    with open(file_path, mode='r', encoding='utf-8-sig') as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames:
            raise ValueError("CSV file is empty or missing headers.")
        
        reader.fieldnames = [str(field).strip().lower() for field in reader.fieldnames]
        
        iterator = iter(reader)
        while True:
            chunk = list(itertools.islice(iterator, chunk_size))
            if not chunk:
                break
            yield chunk

# ==========================================
# 6. REPORTING
# ==========================================
def generate_report(total: int, blocked: int, allowed: int, flagged_domains: Dict[str, List[str]], domain_counts: Counter, elapsed_time: float) -> None:
    """Formats and prints the final analysis report."""
    print("\n" + "="*60)
    print(" DNS THREAT HUNTER SUMMARY ")
    print("="*60)
    print(f"Total Requests Processed: {total:,}")
    print(f"Successfully Blocked:     {blocked:,}")
    print(f"Allowed Traffic:          {allowed:,}")
    print(f"Execution Time:           {elapsed_time:.4f} seconds")
    print("-" * 60)
    
    print("\n🚨 FLAGGED ALLOWED TRAFFIC (REQUIRES REVIEW) 🚨")
    print("-" * 60)
    
    if not flagged_domains:
        print("✅ No suspicious allowed traffic found. Network is clean.")
    else:
        for domain, count in domain_counts.most_common():
            if domain in flagged_domains:
                reasons = " | ".join(flagged_domains[domain])
                print(f"[Count: {count:4}] {domain}")
                print(f"           ↳ Risks: {reasons}")
    print("="*60 + "\n")

# ==========================================
# 7. MAIN CONTROLLER
# ==========================================
def analyze_traffic_parallel(csv_filepath: str) -> None:
    path = Path(csv_filepath)
    logging.info(f"Starting parallel network analysis on {path.name}...")

    start_time = time.time() # ⏱️ START THE CLOCK

    total_requests = 0
    blocked_count = 0
    allowed_count = 0
    flagged_domains: Dict[str, List[str]] = {}
    domain_counts: Counter = Counter()

    try:
        chunks = yield_chunks(path, CHUNK_SIZE)
        
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = executor.map(process_chunk, chunks)
            
            for local_total, local_blocked, local_allowed, local_flagged, local_counts in results:
                total_requests += local_total
                blocked_count += local_blocked
                allowed_count += local_allowed
                domain_counts.update(local_counts)
                
                for dom, risks in local_flagged.items():
                    if dom not in flagged_domains:
                        flagged_domains[dom] = risks

        end_time = time.time() # ⏱️ STOP THE CLOCK
        elapsed = end_time - start_time

        generate_report(total_requests, blocked_count, allowed_count, flagged_domains, domain_counts, elapsed)

    except Exception as e:
        logging.error(f"Analysis failed during processing: {e}")

# ==========================================
# 8. SCRIPT EXECUTION
# ==========================================
if __name__ == "__main__":
    test_file = "DNS_threat_hunter_test2.csv" 
    
    # Generate dummy data mimicking a mix of Cisco and Mosyle formats
    if not Path(test_file).exists():
        with open(test_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Using 'Destination' and 'Policy' (Cisco Umbrella style)
            writer.writerow(['Timestamp', 'Device', 'Destination', 'Policy'])
            for i in range(10000):
                writer.writerow(['10:00', 'Workstation-1', 'xp.itunes-apple.com.akadns.net', 'PASSED'])
            writer.writerow(['10:01', 'Workstation-2', 'pistontomato.endis.it.com', 'PASSED'])       
            writer.writerow(['10:02', 'Workstation-3', 'unblock-roblox.vercel.app', 'PASSED'])       
            writer.writerow(['10:03', 'Workstation-4', 'tiktok.com', 'DENIED'])                      

    analyze_traffic_parallel(test_file)