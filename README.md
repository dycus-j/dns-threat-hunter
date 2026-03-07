DNS Threat Hunter v3.1 🛡️🐍

A high-performance, parallelized security automation tool designed to proactively identify evasive network threats, student-led proxy networks, "Shadow IT," and botnet beacons within enterprise DNS and firewall log exports.

Originally developed to secure a K-12 campus network (Parkhurst Academy), this tool specializes in identifying both widespread proxy bypass attempts and the "Long Tail" of network traffic; that is, those rare, high-entropy anomalies that standard signature-based firewalls often miss.


📌 The Problem: "Living off the Land" & Student Evasion

Modern evasive threats and tech-savvy students no longer rely on "known bad" domains. Instead, they utilize Living off the Land (LotL) tactics:

 - Proxy Networks:
Hosting proxy mirrors on legitimate cloud platforms (Vercel, Replit, Cloudflare Pages) to bypass static category filters.

 - DGA Beacons:
Using Domain Generation Algorithms (DGA) to create high-entropy subdomains for short-lived C2 communication.

 - Identity Masquerading:
Utilizing generic "Cloud Hosting" or "Bot" services that provide a veneer of legitimacy to slip past standard firewall rules.


💡 The Solution: Heuristic Auditing

Instead of relying on static blacklists, DNS Threat Hunter treats security as a mathematical probability. It ingests massive .csv log exports (Meraki, Mosyle, etc.) and runs allowed traffic through a hierarchical Severity Engine.

Advanced Detection Engine:

 - Shannon Entropy Modeling: Mathematically calculates the randomness of a URL to identify machine-generated DGA domains.

 - Recursive Allowlist Verification: Prevents "Subdomain Masquerading" by recursively verifying parent domain integrity.

 - Behavioral Overrides: Automatically flags high-confidence keywords (e.g., proxy, unblock, pish, stay) even when hosted on "trusted" cloud infrastructure.
   

🚀 Technical Features

 - Parallel Processing:
Leverages Python’s concurrent.futures.ProcessPoolExecutor to bypass the Global Interpreter Lock (GIL).Distributed analysis allows the tool to process 150,000+ logs in under 0.6 seconds.

 - Memory Efficiency:
Uses Python Generators (yield) and itertools to maintain a nearly flat memory footprint.

 - Risk Weighting (Severity Engine):
Assigns cumulative scores to domains based on multiple risk vectors (e.g., Cloud Host + Risky TLD + Keyword = Critical Priority).


📊 Professional Reporting Framework

The tool generates a standardized Auditor’s Report (.txt) categorized into three tiers to separate high-volume "noise" from stealthy threats:

 - 🚨 Section 1: Priority Action List:
Critical and High-severity threats requiring immediate manual mitigation or firewall blocking.

 - 📊 Section 2: Recurring Anomalies:
The primary detection zone for student-led proxy rings and unauthorized gaming mirrors. These are medium/low-priority patterns occurring multiple times across the network.

 - 🔍 Section 3: The Long Tail (Patient Zero):
Isolated, single-hit anomalies. This is where stealthy, low-and-slow C2 beacons and one-off phish attempts are identified before they escalate.


🛠️ Usage

 - Export your DNS/Firewall logs as a .csv.

 - Place the file in the project directory (default: DNS_threat_hunter_test.csv).

 - Run the hunter:

  > CLI: $ python dns_threat_hunter_v3.py

 - Review the generated threat_report_[timestamp].txt for actionable intelligence.


🗺️ Future Roadmap

v4.0: 
 - Integration with Cisco Meraki Dashboard API to automatically push "Critical Severity" domains directly to the firewall blocklist.
 - API Enrichment:
   + Dynamic threat-score enrichment via AbuseIPDB and AlienVault OTX.

👨‍💻 Author

James Dycus

IT Operations & Network Engineering

