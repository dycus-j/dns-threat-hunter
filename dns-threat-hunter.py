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

# Configure professional logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# ==========================================
# 1. CONFIGURATION & STATIC THREAT INTEL
# ==========================================
THREAT_INTEL = {
    "keywords": {'proxy', 'unblock', 'bypass', 'games', 'mathway', 'study', 'pish', 'bot', 'tunnel', 'stay'},
    "cloud_hosts": {
        'vercel.app', 'netlify.app', 'onrender.com', 'herokuapp.com', 
        'github.io', 'replit.dev', 'repl.co', 'replit.app', 'firebaseapp.com', 'web.app', 'it.com',
        'webnode.page', 'editmysite.com', 'trycloudflare.com', 'webnode.com', 'pages.dev', 'supabase.co', 'modal.run'
    },
    "suspicious_tlds": {'.xyz', '.top', '.site', '.pw', '.cc', '.tk', '.ml'},
    
    "allowlist": {
        # Core Infrastructure
        'apple.com', 'icloud.com', 'aaplimg.com', 'akadns.net', 'safebrowsing.apple', 'cdn-apple.com', 'apple-dns.net', 'icloud-content.com', 'apple-mapkit.com',
        'microsoft.com', 'office.com', 'office.net', 'azure.com', 'sharepoint.com', 'msedge.net', 'azurefd.net', 'spo-msedge.net', 'ax-msedge.net', 's-msedge.net', 't-msedge.net', 'dual-s-msedge.net', 'ax-dc-msedge.net', 'dual-s-dc-msedge.net', 'azureedge.net', 'ln-msedge.net', 'ln-dc-msedge.net', 'spov-msedge.net', 'wac-msedge.net', 'wac-dc-msedge.net', 'fb-t-msedge.net', 'skype.com', 'cloud.microsoft', 'signalr.net', 'officeapps.live.com', 'msidentity.com', 'windows.net', 'microsoftonline.com', 'live.com', 'svc.ms', 'onecdn.static.microsoft', 'outlook.com', 'tm-azurefd.net', 'microsoftapp.net', 'static.microsoft', 'microsoft.org', 'msftauth.net', 'msecnd.net', 'shopifycloud.com',
        'google.com', 'google', 'firebaseio.com', 'googleusercontent.com', 'doodles.goog', 'gstatic.com', 'googleapis.com', 'run.app', 'googletagservices.com', 'google-analytics.com', 'adtrafficquality.google', 'doubleclick.net', 'googleadservices.com',
        'trafficmanager.net', 'cloudfront.net', 'ssl-images-amazon.com', 'amazon.dev', 'akamai.net', 'akamaized.net', 'akamaiedge.net', 'akamaihd.net', 'amazonaws.com', 'awsglobalaccelerator.com', 'fastly-edge.com', 'fastly.net', 'edgekey.net', 'akaquill.net', 'ccgateway.net', 'sc-gw.com', 'ibyteimg.com', 'capcutcdn-us.com', 'capcutapi.us', 'capcutstatic.com', 'tiktokcdn-us.com', 'tiktokpangle-b.us', 'tiktokpangle-cdn-us.com', 'b-cdn.net', 'cdn77.org', 'brightcovecdn.com', 'edgesuite.net', 'cachefly.net', 'wcdnga.com', 'brightspotcdn.com', 'squarespace-cdn.com', 'cloudinary.com',
        
        # Operational Telemetry & Infrastructure
        'datadoghq.com', 'browser-intake-us5-datadoghq.com', 'browser-intake-datadoghq.com', 'datadoghq-browser-agent.com', 'grafana.net', 'grafana-ops.net', 'cloudflareinsights.com', 'kaltura.com', 'wixmp.com', 'app-analytics-services.com', 'shazamcloud.com', 'qualtrics.com', 'optable.co', 'permutive.app', 'id5-sync.com', 'eu-1-id5-sync.com', 'ipredictive.com', 'bidswitch.net', '3lift.com', 'pubmatic.com', 'stackadapt.com', 'sharethrough.com', 'ltmsphrcl.net', 'newscorp.com', 'omnitagjs.com', 'liveintent.com', 'kueezrtb.com', 'oath.cloud', 'yahoo.com', 'nytimes.com', 'website-files.com', 'mediakind.com', 'zohopublic.com', 'freshworks.com', 'gumroad.com', 'newrelic.com', 'liveperson.net', 'wpmudev.com', 'elasticbeanstalk.com', 'hubspot.com', 'apploversoftware.com', 'sentry.io', 'anyclip.com', 's-onetag.com', 'mediawallahscript.com', 'minutemedia-prebid.com', 'townnews.com', 'puzztake.com', 'emb-api.com', 'brightcove.net', 'dealerinspire.com', 'pubnation.com', 'hubspotusercontent-na1.net', 'klarna.net', 'heart.org', 'kwpubservices.com', 'egnyte.com', 'lightboxcdn.com', 'shemediax.com', '2mdn.net', 'qvdt3feo.com', 'stripe.com', 'impactradius-event.com', 'codecademy.com', 'instapage.com', 'ethyca.com', 'akamaitech.net', 'rigaprecast.com', 'onetrust.com', 'goodhousekeeping.com', 'permutive.com', 'awswaf.com', 'simpleanalyticscdn.com', 'canvacode.com', 'mparticle.com', 'displaynote.com', 'smithsonianmag.com', 'cdn-si-edu.com', 'thirdspacelearning.com', 'prebid.cloud', 'clipart-library.com', 'adobedc.net', 'polygonimages.com', 'ubembed.com', 'inkitt.com', 'app-measurement.com', 'optimizely.com', 'starbucks.com', 'unrulymedia.com', 'webspace-host.com', 'parastorage.com', 'hscollectedforms.net', 'wikimedia.org', 'hcaptcha.com', 'bloodhorse.com', 'convertexperiments.com', 'jwpltx.com', 'jwpsrv.com', 'sendgrid.net', 'adswizz.com', 'librarything.com', 'wgplayer.com', 'relevant-digital.com', 'manager-magazin.de', 'webnovel.com', 'privacy-center.org', 'mediamatters.org', 'medium.com', 'sharethis.com', 'newsbreak.com', 'particlenews.com', 'imyfone.com', 'mochibot.com',

        # Verified Instructional Platforms
        'canva.com', 'canva-apps.com', 'instructure.com', 'inscloudgate.net', 'm-w.com', 'merriam-webster.com', 'duolingo.com', 'getepic.com', 'prodigygame.com', 'savvasrealize.com', 'apptegy.net', 'quizlet.com', 'youversionapi.com', 'biblegateway.com', 'creality.com',
        'blooket.com', 'boddlelearning.com', 'kahoot.it', 'coursearc.com', 'wikiart.org', 'scribdassets.com', 'boddle.com', 'discoveryeducation.com', 'jostens.com', 'yearbookavenue.jostens.com', 'mathjax.org', 'mathswithdavid.com', 'math.bot', 'tvtropes.org', 'simpsonstreetfreepress.org', 'nbcnews.com', 's-nbcnews.com', 'curbsmart.net', 'princetonreview.com', 'stanford.edu', 'penguinmod.com',
        
        # High-Volume Ad-Tech & App Analytics
        'singular.net', 'intergient.com', 'braze.com', 'amplitude.com', 'klaviyo.com', 'playwire.com', 'a-mx.net', 'app-us1.com', 'criteo.com', 'shopifysvc.com', 'quantserve.com', 'pubmnet.com', 'outbrain.com', 'tappx.com', 'intellimizeio.com', 'app-measurement.com', 'visualwebsiteoptimizer.com', 'vidazoo.services', 'wunderkind.co', 'mathtag.com', 'contextweb.com',
        'rubiconproject.com', 'ay.delivery', 'doubleverify.com', 'flashtalking.com', 'appsflyersdk.com', 'adthrive.com', 'raptive.com', 'webpushr.com', 'tremorhub.com', 'fuseplatform.net',
        
        # Internal / Local
        'arpa', 'parkhurst.org', 'lan'
    }
}

RISK_WEIGHTS = {
    "Direct IP Access": 10,       
    "Suspicious Keyword": 5,     
    "Free Cloud/Dev Host": 4,    
    "Risky TLD": 3,              
    "High Entropy": 2,           
    "Suspicious Pattern": 2      
}

# ==========================================
# 2. SCIENTIFIC DETECTION ENGINE
# ==========================================
def calculate_shannon_entropy(data: str) -> float:
    if not data: return 0.0
    entropy = 0
    for count in Counter(data).values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def is_allowed(domain: str) -> bool:
    domain = domain.rstrip('.')
    parts = domain.split('.')
    for i in range(len(parts)):
        test_domain = ".".join(parts[i:])
        if test_domain in THREAT_INTEL["allowlist"]:
            return True
    return False

def get_severity(score: int) -> str:
    if score >= 10: return "CRITICAL"
    if score >= 7:  return "HIGH"
    if score >= 4:  return "MEDIUM"
    return "LOW"

def detect_domain_risks(domain: str) -> Tuple[List[str], int, str]:
    # --- CLEANING PHASE ---
    domain = re.sub(r'^https?://', '', domain)
    if domain.startswith('fe80:') or domain.endswith('.arpa'):
        return [], 0, "CLEAN"

    risks = []
    allowed = is_allowed(domain)
    
    # 1. KEYWORD CHECK
    if any(word in domain for word in THREAT_INTEL["keywords"]):
        if not allowed:
            risks.append("Suspicious Keyword")
    
    # 2. CLOUD HOST CHECK
    is_cloud = any(domain == host or domain.endswith('.' + host) for host in THREAT_INTEL["cloud_hosts"])
    if is_cloud:
        risks.append("Free Cloud/Dev Host")

    # 3. ALLOWLIST GATE
    if allowed and not is_cloud and not risks:
        return [], 0, "CLEAN"

    # 4. HEURISTICS
    if not allowed:
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            risks.append("Direct IP Access")
        if any(domain.endswith(tld) for tld in THREAT_INTEL["suspicious_tlds"]):
            risks.append("Risky TLD")
        
        entropy_score = calculate_shannon_entropy(domain)
        if entropy_score > 3.8:
            risks.append(f"High Entropy")
        elif domain.count('-') > 2 or sum(c.isdigit() for c in domain) > 5:
            risks.append("Suspicious Pattern")

    total_score = sum(RISK_WEIGHTS.get(r, 0) for r in risks)
    severity = get_severity(total_score)
    
    return risks, total_score, severity

# ==========================================
# 3. PARALLEL PROCESSING ENGINE
# ==========================================
def process_chunk(chunk: List[Dict[str, str]]) -> Tuple[int, int, int, Dict[str, Dict], Counter]:
    l_total, l_blocked, l_allowed = 0, 0, 0
    l_flagged, l_counts = {}, Counter()

    for row in chunk:
        l_total += 1
        domain = next((row[k].strip().lower() for k in ['domain', 'url', 'destination', 'query'] if k in row), "")
        action = next((row[k].strip().upper() for k in ['action', 'status', 'policy', 'result'] if k in row), "")

        if not domain or not action: continue

        if any(term in action for term in ['BLOCK', 'DENY', 'DROP', 'REJECT']):
            l_blocked += 1
        elif any(term in action for term in ['ALLOW', 'PASS', 'PERMIT', 'SUCCESS']):
            l_allowed += 1
            risks, score, severity = detect_domain_risks(domain)
            if risks:
                l_counts[domain] += 1
                if domain not in l_flagged: 
                    l_flagged[domain] = {"risks": risks, "score": score, "severity": severity}

    return l_total, l_blocked, l_allowed, l_flagged, l_counts

# ==========================================
# 4. REPORTING (REDUNDANCY REFINED)
# ==========================================
def generate_report(total, blocked, allowed, flagged, counts, elapsed):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    report_file = f"threat_report_{timestamp}.txt"

    out = [
        f"\n",
        "="*90,
        f"🛡️  DNS THREAT HUNTER v3.1 🛡️",
        "="*90,
        f"Audit Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Logs:       {total:,} | Allowed Analyzed: {allowed:,}",
        f"Performance:      {elapsed:.4f}s",
        "-" * 90
    ]

    # Independent Grouping for Redundancy
    priority_alerts = []
    recurring_anomalies = []
    long_tail = []

    for d, meta in flagged.items():
        count = counts[d]
        sev = meta['severity']
        
        # 1. PRIORITY CHECK
        if sev in ("CRITICAL", "HIGH"):
            priority_alerts.append((d, count, meta))
            
        # 2. RECURRING CHECK (Include High Priorities that qualify)
        if count > 1:
            recurring_anomalies.append((d, count, meta))
            
        # 3. LONG TAIL CHECK (Include High Priorities that qualify)
        if count == 1:
            long_tail.append((d, count, meta))

    # SECTION 1: PRIORITY ACTION LIST
    out.append("\n🚨 SECTION 1: PRIORITY ACTION LIST (CRITICAL & HIGH SEVERITY) 🚨")
    out.append("-" * 75)
    if not priority_alerts:
        out.append("✅ No high-priority threats identified.")
    else:
        for d, c, m in sorted(priority_alerts, key=lambda x: (x[2]['score'], x[1]), reverse=True):
            out.append(f"[{m['severity']:8}] [Hits: {c:4}] {d}")
            out.append(f"           ↳ Risks: {', '.join(m['risks'])} (Score: {m['score']})")

    # SECTION 2: RECURRING ANOMALIES
    out.append("\n📊 SECTION 2: RECURRING ANOMALIES (MEDIUM & LOW PATTERNS > 1 HIT) 📊")
    out.append("-" * 75)
    if not recurring_anomalies:
        out.append("✅ No recurring patterns found.")
    else:
        # Sort by hits descending
        for d, c, m in sorted(recurring_anomalies, key=lambda x: x[1], reverse=True)[:50]:
            out.append(f"[{m['severity']:8}] [Hits: {c:4}] {d}")
            out.append(f"           ↳ Risks: {', '.join(m['risks'])}")

    # SECTION 3: THE LONG TAIL
    out.append("\n🔍 SECTION 3: THE LONG TAIL (PATIENT ZERO - EXACTLY 1 HIT) 🔍")
    out.append("-" * 75)
    if not long_tail:
        out.append("✅ No unique single-hit anomalies detected.")
    else:
        # Sort by score descending to find the highest-risk Patient Zero items
        for d, c, m in sorted(long_tail, key=lambda x: (x[2]['score'], x[0]), reverse=True)[:60]:
            out.append(f"[{m['severity']:8}] {d}")
            out.append(f"           ↳ Risks: {', '.join(m['risks'])}")

    final_report = "\n".join(out)
    print(final_report)
    with open(report_file, 'w', encoding='utf-8') as f: f.write(final_report)
    print(f"\n[SUCCESS] Audit Complete. Report saved to: {report_file}")

# ==========================================
# 5. CONTROLLER
# ==========================================
def analyze_traffic(csv_path: str):
    path = Path(csv_path)
    if not path.exists():
        print(f"\n[ERROR] File not found: {csv_path}")
        return

    print(f"\n[INIT] Starting Audit on: {csv_path}")
    start_time = time.time()
    total, blocked, allowed = 0, 0, 0
    flagged, counts = {}, Counter()

    try:
        with open(path, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            headers = [str(n).strip().lower() for n in reader.fieldnames]
            reader.fieldnames = headers
            
            iterator = iter(reader)
            chunks = []
            while True:
                chunk = list(itertools.islice(iterator, 10000))
                if not chunk: break
                chunks.append(chunk)

        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = executor.map(process_chunk, chunks)
            for lt, lb, la, lf, lc in results:
                total += lt; blocked += lb; allowed += la
                counts.update(lc)
                for dom, meta in lf.items():
                    if dom not in flagged: flagged[dom] = meta

        generate_report(total, blocked, allowed, flagged, counts, time.time() - start_time)

    except Exception as e:
        print(f"\n[CRITICAL FAILURE] {e}")
        logging.error(f"Analysis failure: {e}")

if __name__ == "__main__":
    analyze_traffic("DNS_threat_hunter_test.csv")