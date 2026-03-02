import csv
import re
import time
import logging
import itertools
import concurrent.futures
from datetime import datetime
from collections import Counter
from pathlib import Path
from typing import Dict, List, Iterator, Tuple, Set

# Configure professional logging for execution visibility
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# ==========================================
# 1. CONFIGURATION & STATIC THREAT INTEL
# ==========================================
THREAT_INTEL = {
    # Behavior Indicators (Checked FIRST - Overrides Allowlist)
    "keywords": {'proxy', 'unblock', 'bypass', 'games', 'mathway', 'math', 'study', 'free'},
    "cloud_hosts": {
        'vercel.app', 'netlify.app', 'onrender.com', 'herokuapp.com', 
        'github.io', 'replit.dev', 'repl.co', 'replit.app', 'firebaseapp.com', 'web.app', 'it.com',
        'webnode.page', 'editmysite.com', 'trycloudflare.com'
    },
    "suspicious_tlds": {'.xyz', '.top', '.site', '.pw', '.cc', '.tk', '.ml'},
    
    # Static Allowlist (v2.0 baseline for initial push)
    "allowlist": {
        'apple.com', 'icloud.com', 'aaplimg.com', 'akadns.net', 'safebrowsing.apple', 'cdn-apple.com', 'apple-dns.net',
        'microsoft.com', 'office.com', 'office.net', 'azure.com', 'sharepoint.com', 'msedge.net', 'azurefd.net', 'spo-msedge.net', 'ax-msedge.net', 's-msedge.net', 't-msedge.net', 'dual-s-msedge.net', 'ax-dc-msedge.net', 'dual-s-dc-msedge.net', 'azureedge.net', 'ln-msedge.net', 'ln-dc-msedge.net', 'spov-msedge.net', 'wac-msedge.net', 'wac-dc-msedge.net', 'fb-t-msedge.net', 'skype.com', 'cloud.microsoft', 'signalr.net',
        'google.com', 'firebaseio.com', 'googleusercontent.com', 'doodles.goog', 'gstatic.com', 'googleapis.com', 'run.app', 
        'trafficmanager.net', 'cloudfront.net', 'ssl-images-amazon.com', 'amazon.dev', 'akamai.net', 'akamaized.net', 'akamaiedge.net', 'akamaihd.net', 'amazonaws.com', 'awsglobalaccelerator.com', 'fastly-edge.com', 'fastly.net', 'ccgateway.net', 'sc-gw.com', 'ibyteimg.com', 'capcutcdn-us.com', 'capcutapi.us', 'capcutstatic.com', 'tiktokcdn-us.com', 'tiktokpangle-b.us', 'tiktokpangle-cdn-us.com', 'b-cdn.net', 'cdn77.org', 'brightcovecdn.com', 
        'playwire.com', 'intergient.com', 'getepic.com', 'duolingo.com', 'prodigygame.com', 'savvasrealize.com', 'id5-sync.com', 'eu-1-id5-sync.com', 'wixmp.com', 'youversionapi.com', 'sharethrough.com', 'grafana.net', 'grafana-ops.net', 'intellimizeio.com', 'canva.com', 'canva-apps.com', 'instructure.com', 'inscloudgate.net', 'm-w.com', 'merriam-webster.com', 'perchance.org', 'editmysite.com', 'optimizely.com', 'study.com', 'theastudy.com', 'apptegy.net', 'datadoghq.com', 'browser-intake-us5-datadoghq.com', 'indexww.com', 'permutive.app', 'optable.co', 'smaato.net', 'sendgrid.net', 'mathtag.com', 'igodigital.com', 'shazamcloud.com', 'wpeproxy.com', 's-onetag.com', 'aniview.com', 'bidswitch.net', 'qualtrics.com', 'ipredictive.com', 'openwebmp.com', 'rfihub.com', 'arcpublishing.com', 'crowdin.net', 'mktoresp.com', 'swymrelay.com', 'oath.cloud', 'ltmsphrcl.net', 'manager-magazin.de', 'tvtropes.org',
        'mathway.com', 'mathpapa.com', 'mathster.com', 'arpa' 
    }
}

# ==========================================
# 2. HEURISTIC DETECTION ENGINE
# ==========================================
def is_allowed(domain: str) -> bool:
    """
    Recursive subdomain lookup.
    Example: If 'google.com' is in allowlist, 'api.dev.google.com' is allowed.
    """
    domain = domain.rstrip('.') # Handle FQDN trailing dots
    parts = domain.split('.')
    # Recursively check parent domains (O(1) lookup in Set)
    for i in range(len(parts)):
        test_domain = ".".join(parts[i:])
        if test_domain in THREAT_INTEL["allowlist"]:
            return True
    return False

def detect_domain_risks(domain: str) -> List[str]:
    """
    Priority-based Analysis (Heuristic Hierarchy):
    1. Behavior Indicators (Keywords/Cloud Hosts)
    2. Identity Verification (Recursive Allowlist)
    3. Anomaly Heuristics (Entropy/TLDs)
    """
    risks = []
    
    # 1. BEHAVIOR INDICATORS
    if any(word in domain for word in THREAT_INTEL["keywords"]):
        risks.append("Suspicious Keyword")
    
    # Cloud host check handles subdomains (e.g., test.replit.dev)
    is_cloud = any(domain == host or domain.endswith('.' + host) for host in THREAT_INTEL["cloud_hosts"])
    if is_cloud:
        risks.append("Free Cloud/Dev Host")

    # 2. ALLOWLIST GATE
    allowed = is_allowed(domain)
    
    # REFINEMENT: If whitelisted, we suppress noise UNLESS it's a cloud-host.
    if allowed and not is_cloud:
        return []

    # 3. HEURISTICS (Only for Non-Allowed or Cloud-Override traffic)
    if not allowed:
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            risks.append("Direct IP Access")
        if any(domain.endswith(tld) for tld in THREAT_INTEL["suspicious_tlds"]):
            risks.append("Risky TLD")
        # Flags auto-generated domains or long random strings
        if domain.count('-') > 2 or sum(c.isdigit() for c in domain) > 5:
            risks.append("High Entropy (Auto-generated)")

    return risks

# ==========================================
# 3. PARALLEL PROCESSING ENGINE
# ==========================================
def process_chunk(chunk: List[Dict[str, str]]) -> Tuple[int, int, int, Dict[str, List[str]], Counter]:
    """Worker function for concurrent processing of log chunks."""
    l_total, l_blocked, l_allowed = 0, 0, 0
    l_flagged: Dict[str, List[str]] = {}
    l_counts = Counter()

    for row in chunk:
        l_total += 1
        # Normalize column names
        domain = next((row[k].strip().lower() for k in ['domain', 'url', 'destination', 'query'] if k in row), "")
        action = next((row[k].strip().upper() for k in ['action', 'status', 'policy', 'result'] if k in row), "")

        if not domain or not action: continue

        if any(term in action for term in ['BLOCK', 'DENY', 'DROP', 'REJECT']):
            l_blocked += 1
        elif any(term in action for term in ['ALLOW', 'PASS', 'PERMIT', 'SUCCESS']):
            l_allowed += 1
            
            # Heuristic Review
            risks = detect_domain_risks(domain)
            if risks:
                l_counts[domain] += 1
                if domain not in l_flagged: 
                    l_flagged[domain] = risks

    return l_total, l_blocked, l_allowed, l_flagged, l_counts

# ==========================================
# 4. REPORTING & FILE GENERATION
# ==========================================
def generate_report(total, blocked, allowed, flagged, counts, elapsed):
    """Generates a professional TXT report and outputs a console summary."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    report_file = f"threat_report_{timestamp}.txt"
    
    # Pivot: 2+ hits is a Recurring Pattern; 1 hit is Patient Zero
    ANOMALY_THRESHOLD = 2

    out = [
        f"\n",
        "="*60,
        f"🛡️  DNS THREAT HUNTER v2.0 - HEURISTIC + RECURRING ANALYSIS",
        "="*60,
        f"Audit Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Logs:       {total:,}",
        f"Allowed Analyzed: {allowed:,}",
        f"Performance:      {elapsed:.4f}s",
        "-" * 60,
        f"\n🚨 TOP RECURRING THREAT VECTORS (patterns with {ANOMALY_THRESHOLD}+ hits) 🚨\n"
    ]
    
    # Section: High Volume (established patterns)
    recurring = [d for d, c in counts.items() if c >= ANOMALY_THRESHOLD]
    sorted_recurring = sorted(recurring, key=lambda x: counts[x], reverse=True)
    
    for d in sorted_recurring[:35]:
        out.append(f"[Count: {counts[d]:4}] {d}")
        out.append(f"           ↳ Risks: {', '.join(flagged[d])}")

    # Section: The Long Tail (Anomaly Detection)
    out.append(f"\n🔍 ANOMALY DETECTION (under {ANOMALY_THRESHOLD} hits - 'PATIENT ZERO' EVENTS) 🔍\n")
    anomalies = [d for d, c in counts.items() if c < ANOMALY_THRESHOLD]
    sorted_anomalies = sorted(anomalies, key=lambda x: counts[x], reverse=True)
    
    for d in sorted_anomalies[:35]:
        out.append(f"[Count: {counts[d]:4}] {d}")
        out.append(f"           ↳ Risks: {', '.join(flagged[d])}")
    
    final_report = "\n".join(out)
    print(final_report)
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(final_report)
    logging.info(f"Audit Persistence Complete: {report_file}")

# ==========================================
# 5. CONTROLLER
# ==========================================
def analyze_traffic(csv_path: str):
    """Main controller for log analysis pipeline."""
    path = Path(csv_path)
    if not path.exists():
        logging.error(f"Target log file not found: {csv_path}")
        return

    start_time = time.time()
    total, blocked, allowed = 0, 0, 0
    flagged, counts = {}, Counter()

    try:
        # Step 1: Ingest Data using Generators and itertools for memory efficiency
        with open(path, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            reader.fieldnames = [str(n).strip().lower() for n in reader.fieldnames]
            iterator = iter(reader)
            chunks = []
            while True:
                chunk = list(itertools.islice(iterator, 10000))
                if not chunk: break
                chunks.append(chunk)

        # Step 2: Parallel Execution across CPU Cores
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = executor.map(process_chunk, chunks)
            for lt, lb, la, lf, lc in results:
                total += lt; blocked += lb; allowed += la
                counts.update(lc)
                for dom, r in lf.items():
                    if dom not in flagged: flagged[dom] = r

        # Step 3: Final Reporting
        generate_report(total, blocked, allowed, flagged, counts, time.time() - start_time)

    except Exception as e:
        logging.error(f"Analysis pipeline failure: {e}")

if __name__ == "__main__":
    analyze_traffic("DNS_threat_hunter_test2.csv")