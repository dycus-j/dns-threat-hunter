import csv
import re
import time
import math
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
        'webnode.page', 'editmysite.com', 'trycloudflare.com', 'webnode.com'
    },
    "suspicious_tlds": {'.xyz', '.top', '.site', '.pw', '.cc', '.tk', '.ml'},
    
    # Static Allowlist (v2.2 Refined baseline)
    "allowlist": {
        # Core Infrastructure
        'apple.com', 'icloud.com', 'aaplimg.com', 'akadns.net', 'safebrowsing.apple', 'cdn-apple.com', 'apple-dns.net', 'icloud-content.com',
        'microsoft.com', 'office.com', 'office.net', 'azure.com', 'sharepoint.com', 'msedge.net', 'azurefd.net', 'spo-msedge.net', 'ax-msedge.net', 's-msedge.net', 't-msedge.net', 'dual-s-msedge.net', 'ax-dc-msedge.net', 'dual-s-dc-msedge.net', 'azureedge.net', 'ln-msedge.net', 'ln-dc-msedge.net', 'spov-msedge.net', 'wac-msedge.net', 'wac-dc-msedge.net', 'fb-t-msedge.net', 'skype.com', 'cloud.microsoft', 'signalr.net', 'officeapps.live.com', 'msidentity.com', 'windows.net', 'microsoftonline.com', 'live.com', 'svc.ms', 'onecdn.static.microsoft', 'outlook.com', 'tm-azurefd.net',
        'google.com', 'google', 'firebaseio.com', 'googleusercontent.com', 'doodles.goog', 'gstatic.com', 'googleapis.com', 'run.app', 'googletagservices.com', 'google-analytics.com', 'adtrafficquality.google', 'doubleclick.net',
        'trafficmanager.net', 'cloudfront.net', 'ssl-images-amazon.com', 'amazon.dev', 'akamai.net', 'akamaized.net', 'akamaiedge.net', 'akamaihd.net', 'amazonaws.com', 'awsglobalaccelerator.com', 'fastly-edge.com', 'fastly.net', 'edgekey.net', 'akaquill.net', 'ccgateway.net', 'sc-gw.com', 'ibyteimg.com', 'capcutcdn-us.com', 'capcutapi.us', 'capcutstatic.com', 'tiktokcdn-us.com', 'tiktokpangle-b.us', 'tiktokpangle-cdn-us.com', 'b-cdn.net', 'cdn77.org', 'brightcovecdn.com', 
        
        # Operational Telemetry & Infrastructure (Suppressing high-entropy math noise)
        'datadoghq.com', 'browser-intake-us5-datadoghq.com', 'browser-intake-datadoghq.com', 'datadoghq-browser-agent.com', 'grafana.net', 'grafana-ops.net', 'cloudflareinsights.com', 'kaltura.com', 'wixmp.com', 'app-analytics-services.com', 'shazamcloud.com', 'qualtrics.com', 'optable.co', 'permutive.app', 'id5-sync.com', 'ipredictive.com', 'bidswitch.net', '3lift.com', 'pubmatic.com', 'stackadapt.com', 'sharethrough.com', 'ltmsphrcl.net', 'newscorp.com', 'omnitagjs.com', 'liveintent.com', 'kueezrtb.com', 'oath.cloud', 'yahoo.com',

        # Verified Instructional Platforms
        'canva.com', 'canva-apps.com', 'instructure.com', 'inscloudgate.net', 'm-w.com', 'merriam-webster.com', 'duolingo.com', 'getepic.com', 'prodigygame.com', 'savvasrealize.com', 'apptegy.net', 'quizlet.com', 'youversionapi.com', 'biblegateway.com', 'creality.com',
        
        # High-Volume Ad-Tech (Silencing corporate telemetry noise)
        'rubiconproject.com', 'ay.delivery', 'doubleverify.com', 'flashtalking.com', 'appsflyersdk.com', 'adthrive.com', 'raptive.com', 'webpushr.com', 'tremorhub.com', 'fuseplatform.net',
        
        # Internal / Local
        'arpa', 'parkhurst.org'
    }
}

# ==========================================
# 2. SCIENTIFIC DETECTION ENGINE
# ==========================================
def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon Entropy of a string.
    Measures the randomness/complexity. Higher scores (> 3.8) often indicate DGAs or proxies.
    """
    if not data: return 0.0
    entropy = 0
    for count in Counter(data).values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def is_allowed(domain: str) -> bool:
    """Recursive subdomain lookup."""
    domain = domain.rstrip('.')
    parts = domain.split('.')
    for i in range(len(parts)):
        test_domain = ".".join(parts[i:])
        if test_domain in THREAT_INTEL["allowlist"]:
            return True
    return False

def detect_domain_risks(domain: str) -> List[str]:
    """
    Refined Heuristic Hierarchy:
    1. Behavior Indicators (Keywords/Cloud Hosts)
    2. Identity Verification (Recursive Allowlist)
    3. Mathematical Heuristics (Shannon Entropy/TLDs)
    """
    risks = []
    
    # 1. BEHAVIOR INDICATORS (Check for unblocked hosts like webnode.page)
    if any(word in domain for word in THREAT_INTEL["keywords"]):
        risks.append("Suspicious Keyword")
    
    is_cloud = any(domain == host or domain.endswith('.' + host) for host in THREAT_INTEL["cloud_hosts"])
    if is_cloud:
        risks.append("Free Cloud/Dev Host")

    # 2. ALLOWLIST GATE
    allowed = is_allowed(domain)
    # REFINEMENT: Suppress noise on whitelisted domains UNLESS it's a cloud host.
    if allowed and not is_cloud:
        return []

    # 3. SCIENTIFIC HEURISTICS
    if not allowed:
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            risks.append("Direct IP Access")
        if any(domain.endswith(tld) for tld in THREAT_INTEL["suspicious_tlds"]):
            risks.append("Risky TLD")
        
        # Shannon Entropy Check
        entropy_score = calculate_shannon_entropy(domain)
        if entropy_score > 3.8:
            risks.append(f"High Entropy ({entropy_score})")
        elif domain.count('-') > 2 or sum(c.isdigit() for c in domain) > 5:
            risks.append("Suspicious Pattern")

    return risks

# ==========================================
# 3. PARALLEL PROCESSING ENGINE
# ==========================================
def process_chunk(chunk: List[Dict[str, str]]) -> Tuple[int, int, int, Dict[str, List[str]], Counter]:
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
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    report_file = f"threat_report_{timestamp}.txt"
    ANOMALY_THRESHOLD = 2

    out = [
        f"\n",
        "="*60,
        f"🛡️  DNS THREAT HUNTER v2.2 - SCIENTIFIC ANALYSIS",
        "="*60,
        f"Audit Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Logs:       {total:,}",
        f"Allowed Analyzed: {allowed:,}",
        f"Performance:      {elapsed:.4f}s",
        "-" * 60,
        f"\n🚨 TOP RECURRING THREAT VECTORS (patterns with {ANOMALY_THRESHOLD}+ hits) 🚨\n"
    ]
    
    # Section: High Volume
    recurring = [d for d, c in counts.items() if c >= ANOMALY_THRESHOLD]
    if not recurring:
        out.append("✅ No active recurring threats determined for this period.\n")
    else:
        sorted_recurring = sorted(recurring, key=lambda x: counts[x], reverse=True)
        for d in sorted_recurring[:35]:
            out.append(f"[Count: {counts[d]:4}] {d}")
            out.append(f"           ↳ Risks: {', '.join(flagged[d])}")

    # Section: The Long Tail
    out.append(f"\n🔍 ANOMALY DETECTION (under {ANOMALY_THRESHOLD} hits - 'PATIENT ZERO' EVENTS) 🔍\n")
    anomalies = [d for d, c in counts.items() if c < ANOMALY_THRESHOLD]
    if not anomalies:
        out.append("✅ No unique network anomalies determined for this period.\n")
    else:
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
    analyze_traffic("DNS_threat_hunter_test.csv")