import csv
import re
import logging
import itertools
import concurrent.futures
from collections import Counter
from pathlib import Path
from typing import Dict, List, Iterator, Tuple, Optional

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
    "suspicious_tlds": {'.xyz', '.top', '.site', '.pw', '.cc', '.tk', '.ml'}
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
    # Potential column names for the URL/Domain
    domain_keys = ['domain', 'url', 'destination', 'query']
    # Potential column names for the Allow/Block status
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
# def batch_analyze_with_llm(domains: List[str]) -> Dict[str, str]:
#     """
#     [FUTURE INTEGRATION]: Gemini API Batch Processing.
#     Takes a list of suspicious domains and sends ONE bulk request to the LLM.
#     Returns a dictionary of {domain: "AI Risk Reason"} for those flagged.
#     """
#     if not domains:
#         return {}
#        
#     # TODO: Implement Gemini API REST call here.
#     # Example Prompt: "Analyze this list of domains and return a JSON of only the malicious proxies: {domains}"
#     return {}

def detect_domain_risks(domain: str) -> List[str]:
    """Analyzes a domain against static risk vectors ONLY (Fast execution)."""
    risks = []

    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        risks.append("Direct IP Access")
    if any(domain.endswith(host) for host in THREAT_INTEL["cloud_hosts"]):
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
        
        # Normalize the data regardless of the firewall vendor
        domain, action = extract_standard_fields(row)

        if not domain or not action:
            continue

        # Cisco/Meraki often use 'DENIED', Mosyle uses 'BLOCK'
        if action in ('BLOCK', 'DENIED', 'BLOCKED'):
            local_blocked += 1
        elif action in ('ALLOW', 'ALLOWED', 'PASSED'):
            local_allowed += 1
            
            # Run the domain through the Static Threat Engine
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
        
        # Convert headers to lowercase to help the normalizer
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
def generate_report(total: int, blocked: int, allowed: int, flagged_domains: Dict[str, List[str]], domain_counts: Counter) -> None:
    """Formats and prints the final analysis report."""
    print("\n" + "="*60)
    print("🛡️  ENTERPRISE DNS THREAT SUMMARY (PARALLELIZED)")
    print("="*60)
    print(f"Total Requests Processed: {total:,}")
    print(f"Successfully Blocked:     {blocked:,}")
    print(f"Allowed Traffic:          {allowed:,}")
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

        # --- [FUTURE] AI BATCH PROCESSING PHASE ---
        # We only send domains that looked weird (e.g., High Entropy) to the AI for verification
        # domains_for_ai = [dom for dom, risks in flagged_domains.items() if "High Entropy (Auto-generated)" in risks or "Free Cloud/Dev Host" in risks]
        # 
        # if domains_for_ai:
        #     logging.info(f"Sending {len(domains_for_ai)} suspicious domains to Gemini AI for batch analysis...")
        #     ai_results = batch_analyze_with_llm(domains_for_ai)
        #     
        #     # Merge the AI's findings back into our main report
        #     for dom, ai_flag in ai_results.items():
        #         if dom in flagged_domains:
        #             flagged_domains[dom].append(f"AI Flag: {ai_flag}")

        # --- FINAL REPORTING ---
        generate_report(total_requests, blocked_count, allowed_count, flagged_domains, domain_counts)

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