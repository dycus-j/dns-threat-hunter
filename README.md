DNS Threat Hunter 🛡️

A lightweight, high-performance Python threat hunting tool designed for IT Administrators and Network Defenders. This script parses massive DNS and Web Filter logs (originally designed for Mosyle MDM exports, but easily adaptable) to proactively identify network bypass attempts, web proxies, and suspicious cloud-hosted traffic.

📌 The Problem

Users frequently attempt to bypass corporate or CIPA-compliant web filters using newly generated proxy sites (e.g., CroxyProxy) or by hosting their own proxy tunnels on free developer platforms (Vercel, GitHub Pages, Render). Because these domains are constantly changing, static MDM and firewall blacklists often miss them.

💡 The Solution

Instead of manually scrolling through thousands of lines of normal ecosystem traffic, this script ingests a .csv log export, filters out the noise, and runs the "Allowed" traffic against a custom Threat Intelligence engine.

It automatically flags domains based on:

Direct IP Access (bypassing DNS resolution).

Risky TLDs (e.g., .xyz, .top, .tk).

Developer Cloud Hosts commonly used for proxy tunneling.

High Entropy URLs (auto-generated domains).

Suspicious Keywords.

🚀 Features

Parallel Processing Engine: Utilizes Python's concurrent.futures.ProcessPoolExecutor to bypass the Global Interpreter Lock (GIL), distributing log ingestion across multiple CPU cores to evaluate multi-million row exports in seconds.

Memory Efficient: Uses Python Generators (yield) and itertools to process logs in manageable chunks, preventing RAM crashes on massive CSV exports.

Modular Design: Built with strict Separation of Concerns (SoC). The Threat Intelligence logic, I/O ingestion, and Reporting engine are fully isolated.

Resilient Parsing: Automatically normalizes column headers to account for vendor changes in log export formatting.

🗺️ Future Roadmap (v2.0)

LLM / AI Integration: Implement a batch-processing REST API call to Google's Gemini LLM. Instead of querying the AI for every log entry, the script will bundle high-entropy/unknown domains into a single JSON payload for AI-driven heuristic analysis to catch zero-day proxy patterns.

Automated Threat Feeds: Integrate dynamic pulls from open-source threat intelligence feeds (e.g., AbuseIPDB) to replace the static dictionary.

🛠️ Usage

Export your DNS/Web Filter logs as a .csv.

Place the .csv in the same directory as the script (or update the file path in the __main__ block).

Run the analyzer:

<!-- end list -->

python dns_threat_hunter.py


Review the flagged domains in the terminal output and add them to your firewall or MDM Blacklist.

👨‍💻 Author

James Dycus

IT Support Specialist & Network Technician

LinkedIn

