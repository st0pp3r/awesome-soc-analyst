# Awesome SOC Analyst 
[![URL Check](https://github.com/st0pp3r/Supreme-SOC-Analyst/actions/workflows/url_check.yml/badge.svg)](https://github.com/st0pp3r/Supreme-SOC-Analyst/actions/workflows/url_check.yml/badge.svg) [![Create Bookmarks File](https://github.com/st0pp3r/Supreme-SOC-Analyst/actions/workflows/create_bookmarks.yml/badge.svg)](https://github.com/st0pp3r/Supreme-SOC-Analyst/actions/workflows/create_bookmarks.yml)

Online resources related to the role of the SOC Analyst. I will include mostly resources that are tailored to the role of SOC Analyst and not the field of cyber security in general.

## Contents

- [Event Log References](#event-log-references) - Online vendor documentation and references for event logs. 
- [Sandboxes](#sandboxes) - Online sandboxes to analyze malware behavior safely.  
- [IOC Lookups](#ioc-lookups) - Services for checking indicators of compromise (IOCs) like hashes, domains, and IPs.  
- [Emails](#emails) - Tools for investigating email headers.
- [EXE Lookup](#exe-lookup) - Resources for checking executables..  
- [Lookup Services](#lookup-services) - General lookup tools for domains, IPs, and other artifacts.  
- [Fingerprinting](#fingerprinting) - Online fingerprinting services.  
- [Scanning](#scanning) - Network scanning tools for reconnaissance.  
- [URL Scan](#url-scan) - Services to analyze URLs and inspect web content.  
- [DNS](#dns) - Tools for DNS resolution and tracking domain history.  
- [MAC Lookup](#mac-lookup) - Lookup services for MAC addresses to identify device manufacturers.  
- [ASN](#asn) - Tools for finding autonomous system numbers (ASNs) and related IP allocations.  
- [Browser Extension](#browser-extension) - Security-focused browser add-ons for analysis and protection.  
- [Hash](#hash) - Hashing tools.  
- [Misc Tools](#misc-tools) - Various cybersecurity utilities that don’t fit into a specific category.  
- [Resources](#resources) - Collections of useful cybersecurity websites, documents, and reference materials.  
- [Blogs](#blogs) - Security-focused blogs with insights, analysis, and threat intelligence.  
- [Newsletters](#newsletters) - Regular updates and summaries of cybersecurity trends and incidents.  
- [Good Reads](#good-reads) - Interesting articles and reports related to cybersecurity.  
- [Books](#books) - Recommended reading on cybersecurity, hacking, and digital forensics.  
- [Training](#training) - Online courses, certifications, and training platforms for cybersecurity skills. 
- [Podcasts](#podcasts) - Audio discussions on cybersecurity, hacking, and threat intelligence.  
- [Twitter/X](#twitterx) - Security experts, researchers, and threat intelligence feeds to follow.  
- [Interview Questions](#interview-questions) - Common cybersecurity interview questions and preparation resources.


### Sandboxes
- [VirusTotal](https://www.virustotal.com/gui/home/search) - Analyze suspicious files, domains, IPs and URLs to detect malware and other breaches.
- [Hybrid Analysis](https://www.hybrid-analysis.com/) - Free malware analysis service for the community that detects and analyzes unknown threats.
- [AnyRun](https://app.any.run/) - Interactive malware analysis sandbox.
- [Triage | Recorded Future ](https://tria.ge/s) -  Malware analysis sandbox.
- [JOE Sandbox Cloud Basic](https://www.joesandbox.com/#windows) -  Malware analysis sandbox.
- [Threat Zone](https://app.threat.zone/scan) - Holistic malware analysis platform - interactive sandbox, static analyzer, emulation, URL Analyzer.
- [Filescan.io](https://www.filescan.io/scan) - Insightful Malware Analysis Powered by Emulation.
- [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) - Engine powered by ReversingLabs Titanium Platform
- [DOGGuard](https://app.docguard.io/) - Analyze files, Hashes and URLs.

### IOC Lookups
- [VirusTotal](https://www.virustotal.com/#/home/search) - URL, IP Address, Domain, Hash.
- [Cisco Talos Intelligence](https://talosintelligence.com/) - IP, URL, Domain, Hash
- [AbuseIPDB](https://www.abuseipdb.com/) - IP Address, Subnet, Domain
- [SpamHaus](https://check.spamhaus.org/) - IP, Domain, ASN, SBL, Email, Hash
- [MalwareBazaar](https://bazaar.abuse.ch/browse/) - Hash
- [URLHaus](https://urlhaus.abuse.ch/browse/) - Domain, URL, Hash
- [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) - IP, URL, Hash
- [ThreatFox IOC Database](https://threatfox.abuse.ch/browse/) - IP, Domain, URL, Hash
- [GreyNoise](https://viz.greynoise.io/) - IP
- [Pulsedive](https://pulsedive.com/analyze/) - IP, URL, Domain
- [threatbook](https://threatbook.io/) - IP, Domain
- [FortiGuard Labs](https://www.fortiguard.com/search) - IP, Domain, URL
- [Spamhaus IP Reputation](https://www.spamhaus.org/ip-reputation/) and [Spamhaus Domain Reputation](https://www.spamhaus.org/domain-reputation/)
- [Palo Alto URL](https://urlfiltering.paloaltonetworks.com/query/) - URL
- [DOGGuard](https://app.docguard.io/) - Analyze files, Hashes and URLs.

### Emails
- [MXToolbox Emails](https://mxtoolbox.com/NetworkTools.aspx?tab=Email) - DMARC. SPF, DKIM, Header Analyzer

### EXE Lookup
- [EchoTrail](https://www.echotrail.io/insights) - Look up information about known files using hash or process name.
- [XCyclopedia](https://strontic.github.io/xcyclopedia/index) - Look up information about known exe files - hashes, known paths, metadata, other.

### Lookup Services
- [IPVOID](https://www.ipvoid.com/) - IP, DNS , URL, Text Manipulation
- [MXToolbox](https://mxtoolbox.com/) - Email, Network, DNS, Websites
- [HackerTarget](https://hackertarget.com/)
- [ViewDNS](https://viewdns.info/)

### Fingerprinting
 - [Censys](https://search.censys.io/)
 - [Shodan](https://www.shodan.io/)
 - [ZoomEye](https://www.zoomeye.ai/)
 - [Onyphe](https://search.onyphe.io/)
 - [FOFA](https://en.fofa.info/)

### Scanning
 - [MXToolbox Network Tools](https://mxtoolbox.com/NetworkTools.aspx?tab=Network) - Port status, ICMP, Trace.
 - [Hacker Target](https://hackertarget.com/) - Port scanner, Vulnerability scanner, Web scanner, CMS Scanner

### URL Scan
- [VirusTotal](https://www.virustotal.com/#/home/search) - Scans provided URLs.
- [urlscan.io](https://urlscan.io/) - Page source code, requests analysis.
- [Cloudflare Radar URL Scan](https://radar.cloudflare.com/scan) - Gives you information about cookies, technology used, SSL certificates, headers and dns records and other.
- [URLVoid](https://www.urlvoid.com/) - Reputation check
- [URLQuery](https://urlquery.net/search) -  Very nice analysis of the the scanned URL along with reputation check.
- [CyberGordon](https://cybergordon.com/) - Multiple engines scan.
- [Tiny Scan](https://www.tiny-scan.com/) - Gives you information about cookies, technology used, SSL certificates, headers and dns records and other.
- [CheckPhish](https://checkphish.bolster.ai/) - Check if URL is phishing.
- [PhishTank](https://phishtank.org/) - Check if URL is phishing
- [HTTPStatus.io](https://httpstatus.io/) - Check URLs.

### DNS
 - [MXToolbox DNS](https://mxtoolbox.com/NetworkTools.aspx?tab=DNS) - DNS tools.
 - [DNS Dumpster](https://dnsdumpster.com/) - DNS records.
 - [DNS History](https://dnshistory.org/) - Historical DNS records.

### MAC Lookup
- [Wireshark OUI Lookup](https://www.wireshark.org/tools/oui-lookup.html) - Information about manufacturers.

### ASN
 - [ASN LookUp](https://asnlookup.com/)
 - [Hacker Target ASN Lookup](https://hackertarget.com/as-ip-lookup/)
 - [MXToolbox ASN Lookup](https://mxtoolbox.com/asn.aspx)

### Browser Extension
- [CRXaminer](https://crxaminer.tech/) - Chrome extension analyzer.

### Hash
 - [Hash Calculator](https://md5calc.com/hash) - Calculator for hashes.

### Misc Tools
 - [WayBack Machine](https://web.archive.org/) - Historical search of pages.
 - [RedHunt Labs Online Paste Tools Lookup](https://redhuntlabs.com/online-ide-search/) - Lookup keywords on online paste sites like pastebin.
 - [de4js](https://lelinhtinh.github.io/de4js/) - JavaScript Deobfuscator and Unpacker.
 - [deobfuscate.relative.im](https://deobfuscate.relative.im/) - JavaScript Deobfuscator.
 - [A-Packets PCAP Aalyzer](https://apackets.com/) - PCAP analyzer from A-Packets.
 - [URLEncoder](https://www.urlencoder.org/) - URL encoder and decoder.
 - [explainshell.com](https://explainshell.com/) - Write down a command-line to see the help text that matches each argument
 - [Crontab Guru](https://crontab.guru) - The quick and simple editor for cron schedule expressions.
 - [Subnet Calculator](https://mxtoolbox.com/subnetcalculator.aspx) -  Enter a subnet range (CIDR) and see IP address information about that range.
 - [EpochConverter](https://www.epochconverter.com/) - Epoch & Unix Timestamp Conversion Tools.
 - [Cyberchef](https://cyberchef.org/) - Data transformation.
 - [10 minute mail](https://10minutemail.com/) - Can be used for registrations.

### Resources
- [MITRE ATT&CK®](https://attack.mitre.org/) - MITRE ATT&CK knowledge base of adversary tactics and techniques.
- [MITRE D3fend](https://d3fend.mitre.org/) - A knowledge of cybersecurity countermeasures
- [Cyber Kill Chain | Lockheed Martin](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) - Model for identification and prevention of cyber intrusions activity.
- [Speedguide.net Port Information](https://www.speedguide.net/ports.php) - Port information and common apps.

### Blogs

### Newsletters

### Good Reads

### Books
- [Blue Team Handbook: SOC, SIEM, and Threat Hunting](https://www.amazon.com/Blue-Team-Handbook-Condensed-Operations/dp/1091493898)
- [Blue Team Handbook: Incident Response Edition](https://www.amazon.com/Blue-Team-Handbook-condensed-Responder/dp/1500734756)
- [Effective Threat Investigation for SOC Analysts: The ultimate guide to examining various threats and attacker techniques using security logs](https://www.packtpub.com/en-gr/product/effective-threat-investigation-for-soc-analysts-9781837634781)
- [BTFM: Blue Team Field Manual](https://www.amazon.com/Blue-Team-Field-Manual-BTFM/dp/154101636X)

### Training
- [LetsDefend SOC Analyst Path](https://app.letsdefend.io/path/soc-analyst-learning-path)
- [TCM Security Security Operations (SOC) 101](https://academy.tcm-sec.com/p/security-operations-soc-101)
- [TCM Security Security SOC Level 1 Live Training](https://certifications.tcm-sec.com/product/soc-level-1-live-training/)
- [Security Blue Team L1](https://www.securityblue.team/certifications/blue-team-level-1)
- [Security Blue Team L2](https://www.securityblue.team/certifications/blue-team-level-2)
- [HackTheBox Academy SOC Analyst](https://academy.hackthebox.com/path/preview/soc-analyst)
- [TryHackMe SOC Simulator](https://tryhackme.com/r/soc-sim/?ref=nav)
- [TryHackMe SOC Level 1 Training Path](https://tryhackme.com/r/path/outline/soclevel1)
- [TryHackMe SOC Level 2 Training Path](https://tryhackme.com/r/path/outline/soclevel2)
- [Constructing Defense](https://course.constructingdefense.com/constructing-defense)
- [SANS SEC401: Security Essentials - Network, Endpoint, and Cloud](https://www.sans.org/cyber-security-courses/security-essentials-network-endpoint-cloud/)
- [SANS SEC504: Hacker Tools, Techniques, and Incident Handling](https://www.sans.org/cyber-security-courses/hacker-techniques-incident-handling/)
- [OffSec SOC-200: Foundational Security Operations and Defensive Analysis](https://www.offsec.com/courses/soc-200/)
- [TCM Security Practical SOC Analyst Associate](https://certifications.tcm-sec.com/psaa/)
- [CompTIA CySA+](https://www.comptia.org/certifications/cybersecurity-analyst)
- [CompTIA Security+](https://www.comptia.org/certifications/security)
- [EC-Council Certified SOC Analyst](https://iclass.eccouncil.org/our-courses/certified-soc-analyst-csa)
- [EC-Council Certified Incident Handler](https://iclass.eccouncil.org/our-courses/certified-incident-handler-ecih/)

### Challenges
-[Blue Team Labs Online](https://blueteamlabs.online/) - A gamified platform for defenders to practice their skills in security investigations and challenges covering; Incident Response, Digital Forensics, Security Operations, Reverse Engineering, and Threat Hunting.

### Podcasts
- [Darknet Diaries](https://darknetdiaries.com/) - True stories from the dark side of the Internet.

### Twitter/X

### Podcasts

### Interview Questions
- [SOC Interview Questions | LetsDefend](https://github.com/LetsDefend/SOC-Interview-Questions)