# Awesome SOC Analyst [![Awesome](https://awesome.re/badge.svg)](https://awesome.re) 
[![URL Check](https://github.com/st0pp3r/awesome-soc-analyst/actions/workflows/url_check.yml/badge.svg)](https://github.com/st0pp3r/awesome-soc-analyst/actions/workflows/url_check.yml/badge.svg) [![Create Bookmarks File](https://github.com/st0pp3r/awesome-soc-analyst/actions/workflows/create_bookmarks.yml/badge.svg)](https://github.com/st0pp3r/awesome-soc-analyst/actions/workflows/create_bookmarks.yml)[![Spell Check](https://github.com/st0pp3r/awesome-soc-analyst/actions/workflows/spell_check.yml/badge.svg)](https://github.com/st0pp3r/awesome-soc-analyst/actions/workflows/spell_check.yml)

Online resources for SOC Analysts. Resources related to incident investigation, blogs, newsletters, good reads, books, trainings, podcasts, Twitter/X accounts and a set of online tools for day-to-day investigations. 
The repo generates a bookmark file for easy import to your browser.

I will mostly include resources that are tailored as much as possible to the role of the SOC Analyst and not the field of cyber security in general.

**Contributions are welcome!**

## Contents

- [Resources and Reference Material](#resources-and-reference-material) - Various reference materials, frameworks, and guidelines for cyber defense.
- [Attack Reference Material](#attack-reference-material) - Attack-specific reference materials for understanding tactics, techniques, and procedures.
- [Event Log References](#event-log-references) - Vendor documentation and references for event logs.
- [Blogs](#blogs) - Blogs that offer valuable insights and updates in security and incident handling.
- [Good Reads](#good-reads) - Recommended reading materials for expanding knowledge in cyber defense.
- [Newsletters](#newsletters) - Newsletters that provide curated content and updates in the cyber security space.
- [Podcasts](#podcasts) - Podcasts related to cyber defense, incident response, and security topics.
- [Books](#books) - Books focused on improving knowledge and skills in cyber defense and security.
- [Training and Certifications](#training-and-certifications) - Training programs and certifications relevant to security operations and incident response.
- [Twitter/X](#twitterx) - Notable Twitter/X accounts to follow for security updates and news.
- [Interview Questions](#interview-questions) - Sample interview questions for cybersecurity roles, particularly for SOC analysts.
- [Tools](#tools) - A collection of essential tools for security operations, categorized for easy reference:
    - [Sandboxes](#sandboxes) - Sandboxes for safe malware analysis and testing.
    - [IOC Lookups](#ioc-lookups) - Tools for looking up Indicators of Compromise (IOCs).
    - [Emails](#emails) - Tools for analyzing and investigating email headers and email-related data.
    - [Multifunctional LookUp Services](#multifunctional-lookup-services) - Tools for searching multiple data points (IP, URL, Domain, etc.).
    - [Fingerprinting](#fingerprinting) - Tools for identifying and fingerprinting devices and services.
    - [Network Scanning](#network-scanning) - Tools for scanning and analyzing network traffic.
    - [SSL/TLS](#ssltls) - Tools for scanning and analyzing SSL/TLS configurations.
    - [Website Scan](#website-scan) - Tools for scanning websites for security vulnerabilities.
    - [CMS Scan](#cms-scan) - Tools for scanning Content Management Systems (CMS) for vulnerabilities.
    - [URL](#url) - Tools for analyzing and investigating URLs.
    - [DNS](#dns) - Tools for analyzing and querying DNS records.
    - [MAC](#mac) - Tools for looking up and identifying MAC addresses.
    - [ASN](#asn) - Tools for querying ASN information.
    - [Browser Extension](#browser-extension) - Browser extensions for security professionals.
    - [User Agent](#user-agent) - Tools for investigating and analyzing User Agent data.
    - [USB and PCI](#usb-and-pci) - Tools related to USB and PCI devices for security analysis.
    - [EXE Lookup](#exe-lookup) - Tools for analyzing executable files.
    - [Certificate](#certificate) - Tools for analyzing certificates.
    - [Hash](#hash) - Tools for hashing and investigating file hashes.
    - [Misc Tools](#misc-tools) - Miscellaneous tools useful for various security tasks.
    - [Data Manipulation Online Tools](#data-manipulation-online-tools) - Online tools for data manipulation and analysis.

### Resources and Reference Material
- [MITRE ATT&CK®](https://attack.mitre.org/) - MITRE ATT&CK knowledge base of adversary tactics and techniques.
- [MITRE D3fend](https://d3fend.mitre.org/) - A knowledge base of cybersecurity countermeasures
- [Cyber Kill Chain | Lockheed Martin](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) - Model for identification and prevention of cyber intrusions activity.
- [Blue Team Notes | Purp1eW0lf](https://github.com/Purp1eW0lf/Blue-Team-Notes)
- [CVE](https://cve.mitre.org/) - Vulnerability database.
- [Command Line Arguments Docs| ss64](https://ss64.com/) - Command line arguments explanations.
- [Port Information | Speedguide.net](https://www.speedguide.net/ports.php) - Port information and common apps.
- [LOLBAS (Living Off The Land Binaries and Scripts)](https://lolbas-project.github.io/) - Collection of legitimate binaries and scripts abused by attackers.
- [WTFBins](https://wtfbins.wtf/) - Binaries that behaves exactly like malware, except, somehow, they are not.
- [LOLDrivers](https://loldrivers.io/) - Database of drivers used by adversaries to bypass security controls and carry out attacks.
- [GTFOBins](https://gtfobins.github.io/) - Collection binaries that can be used to bypass local security restrictions in misconfigured systems.
- [LOLRMM](https://lolrmm.io/) - Repository of Remote Monitoring and Management (RMM) software that attackers abuse.
- [LOLOLFarm](https://lolol.farm/) - Database of LOL (Living Off The Land) techniques used.
- [Email Headers IANA](https://www.iana.org/assignments/message-headers/message-headers.xhtml) - IANA Email headers reference.
- [DKIM, DMARC, SPF](https://github.com/nicanorflavier/spf-dkim-dmarc-simplified) - Simplified explanation of DKIM, DMARC, SPF.
- [Kerberos Protocol | hackndo](https://en.hackndo.com/kerberos/) - Explanation of Keberos protocol.
- [Service Principal Name (SPN) | hackndo](https://en.hackndo.com/service-principal-name-spn/) - Explanation of SPN.

### Attack Reference Material
- [ADSecurity AD Attacks](https://adsecurity.org/?page_id=4031) - Attacks on Active Directory.
- [Password Spraying | hackndo](https://en.hackndo.com/password-spraying-lockout/) - Explanation of password spraying.
- [Pass-The-Hash | hackndo](https://en.hackndo.com/pass-the-hash/) - Explanation of pass the hash attack.
- [Over Pass-The-Hash](https://medium.com/r3d-buck3t/play-with-hashes-over-pass-the-hash-attack-2030b900562d) - Explanation of over pass the hash attack.
- [Pass the ticket](https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/t1550-use-alternate-authentication-material/pass-the-ticket) - Explanation of over pass the ticket attack.
- [Kerberoasting | adsecurity](https://adsecurity.org/?p=3458) - Explanation of kerberoasting attack.
- [Kerberoasting | hackndo](https://en.hackndo.com/kerberoasting/) - Explanation of kerberoasting attack.
- [Kerberos Unconstrained Delegation | hackndo](https://en.hackndo.com/constrained-unconstrained-delegation/) - Explanation of Kerberos unconstained delegation.
- [AS_REP Roasting | hackndo](https://en.hackndo.com/kerberos-asrep-roasting/) - Explanation of as_rep roasting attack.
- [Golden Ticket | hackndo](https://en.hackndo.com/kerberos-silver-golden-tickets/) - Explanation of golden ticket attack.
- [Silver Ticket | hackndo](https://en.hackndo.com/kerberos-silver-golden-tickets/) - Explanation of silver ticket attack.
- [Skeleton Key | adsecurity](https://adsecurity.org/?p=1255) - Explanation of Skeleton Key attack.
- [NTLM Relay | hackndo](https://en.hackndo.com/ntlm-relay/) - Explanation of NTLM Relay.
- [LLMNR Poisoning](https://medium.com/@rymak/llmnr-poisoning-an-attack-on-the-active-directory-of-an-organization-9907bf0498ff) - Explanation of LLMNR Poisoning.
- [DCSync | adsecurity](https://adsecurity.org/?p=1729) - Explanation of DCSync attack.
- [DNS Tunneling | unit42](https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/) - Simple example of DNS tunneling and how it is abused.
- [DNS DGA | cybereason](https://www.cybereason.com/blog/what-are-domain-generation-algorithms-dga) - Nice examples of DGA variants.

### Event Log References
- [Windows Event IDs and Audit Policies](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Windows Security Log Event IDs Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j)
- [Windows Logon Types](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types)
- [Windows Logon Failure Codes](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4625)
- [Azure SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [Azure SigninLogs Risk Detection](https://learn.microsoft.com/en-us/graph/api/resources/riskdetection?view=graph-rest-1.0)
- [AADSTS Error Codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes#aadsts-error-codes)
- [Microsoft Errors Search](https://login.microsoftonline.com/error)
- [Microsoft Entra authentication and authorization error codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)
- [Microsoft Defender Event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [Microsoft Defender for Cloud Alert References](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)
- [Microsoft Defender for Identity Alert References](https://learn.microsoft.com/en-us/defender-for-identity/alerts-overview)
- [Microsoft Defender XDR Schemas](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [Microsoft DNS Debug Event IDs](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v=ws.11)#dns-logging-and-diagnostics-1)
- [Sysmon Event IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events)
- [Cisco ASA Event IDs](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html)
- [Palo Alto PAN-OS Log Fields](https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions)
- [Palo Alto PAN-OS Threat Categories](https://docs.paloaltonetworks.com/advanced-threat-prevention/administration/threat-prevention/threat-signature-categories)
- [Palo Alto PAN-OS Applications](https://applipedia.paloaltonetworks.com/)
- [FortiGate FortiOS Log Types and Subtypes](https://docs.fortinet.com/document/fortigate/7.6.1/fortios-log-message-reference/160372/list-of-log-types-and-subtypes)
- [FortiGate FortiOS Log Fields](https://docs.fortinet.com/document/fortigate/7.6.1/fortios-log-message-reference/357866/log-message-fields)
- [FortiGate FortiGuard Encyclopedia](https://www.fortiguard.com/encyclopedia?type=ips)
- [GCP Threat Detection Findings](https://cloud.google.com/security-command-center/docs/concepts-security-sources#threats)
- [GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [Barracuda Firewall Log Files Structure and Log Fields](https://campus.barracuda.com/product/cloudgenfirewall/doc/172623663/available-log-files-and-structure)
- [Barracuda Web Security Gateway Log Fields](https://campus.barracuda.com/product/websecuritygateway/doc/168742383/syslog-and-the-barracuda-web-security-gateway/)
- [Barracuda Web Application Firewall Log Format](https://campus.barracuda.com/product/webapplicationfirewall/doc/168312817/log-formats) and [Barracuda Web Application Firewall Log Formats](https://campus.barracuda.com/product/webapplicationfirewall/doc/168312823/exporting-log-formats)
- [Check Point Firewall Log Fields](https://support.checkpoint.com/results/sk/sk144192)
- [Cisco Umbrella Proxy Log Format](https://docs.umbrella.com/deployment-umbrella/docs/proxy-log-formats), [Cisco Umbrella DNS Log Format](https://docs.umbrella.com/deployment-umbrella/docs/dns-log-formats) and [Cisco Umbrella Content Categories](https://docs.umbrella.com/deployment-umbrella/docs/new-content-category-definitions)
- [Cisco WSA Access Log Fields](https://www.cisco.com/c/en/us/td/docs/security/wsa/wsa11-0/user_guide/b_WSA_UserGuide/b_WSA_UserGuide_chapter_010111.html#con_1679851) and [Cisco WSA Filtering Categories](https://www.cisco.com/c/en/us/products/collateral/security/web-security-appliance/datasheet_C78-718442.html)
- [Cisco ESA Log Types](https://www.cisco.com/c/en/us/td/docs/security/esa/esa15-0/user_guide/b_ESA_Admin_Guide_15-0/b_ESA_Admin_Guide_12_1_chapter_0100111.html)
- [Juniper Junos OS Log Fields](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging-for-a-security-device.html)
- [Imperva Log Fields](https://docs.imperva.com/bundle/cloud-application-security/page/more/log-file-structure.htm) and [Imperva Event Types](https://docs.imperva.com/bundle/v15.3-waf-system-events-reference-guide/page/63179.htm)
- [Squid Log Fields and Log Types](https://wiki.squid-cache.org/SquidFaq/SquidLogs) and [Squid Log Format](https://wiki.squid-cache.org/Features/LogFormat)
- [Suricata Log Format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
- [ZScaler Web Log Format](https://help.zscaler.com/zia/nss-feed-output-format-web-logs), [ZScaler Firewall Log Format](https://help.zscaler.com/zia/nss-feed-output-format-firewall-logs), [ZScaler DNS Log Format](https://help.zscaler.com/zia/nss-feed-output-format-dns-logs) and [ZScaler URL Categories](https://help.zscaler.com/zia/about-url-categories).
- [Broadcom Edge Secure Web Gateway (Bluecoat) Access Log Format](https://techdocs.broadcom.com/us/en/symantec-security-software/web-and-network-security/edge-swg/7-4/getting-started/page-help-administration/page-help-logging/log-formats.html) and [Broadcom Edge Secure Web Gateway (Bluecoat) Categories](https://sitereview.bluecoat.com/#/category-descriptions)
- [Broadcom Endpoint Protection Manager Log Format](https://knowledge.broadcom.com/external/article/155205/external-logging-settings-and-log-event.html)
- [SonicWall SonicOS Log Events Documentation](https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-4-log-events-reference-guide.pdf)
- [WatchGuard Fireware OS Log Format](https://www.watchguard.com/help/docs/fireware/12/en-US/log_catalog/12_11_Log-Catalog.pdf)
- [Sophos Firewall Log Documentation](https://docs.sophos.com/nsg/sophos-firewall/19.5/PDF/SF-syslog-guide-19.5.pdf)
- [Sophos Central Admin Events](https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/LogsReports/Logs/Events/EventTypes/index.html#runtime-detections)
- [Apache Custom Log Format](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html)
- [IIS Log File Format](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525807(v=vs.90))
- [NGINX Access Log Format](https://nginx.org/en/docs/http/ngx_http_log_module.html#access_log)

### Blogs
 - [The DFIR Report](https://thedfirreport.com/) - Detailed and thorough analysis of real intrusions.
 - [Bad Sector Labs](https://blog.badsectorlabs.com/) - Good catch all aggregator.
 - [This Week In 4n6](https://thisweekin4n6.com/) - Good catch all aggregator focused a lot on dfir.
 - [SOC Investigation](https://www.socinvestigation.com/) - SOC related articles.
 - [Elastic Security Labs](https://www.elastic.co/security-labs) - Good collection of malware analysis blogposts.
 - [Dark Reading](https://www.darkreading.com/) - Cyber security news.
 - [Bleeping Computer](https://www.bleepingcomputer.com/) - Cyber security news.
 - [The Hacker News](https://thehackernews.com/) - Cyber security news.

### Good Reads
 - [A Tour Inside a SOC Analyst Mind | Ali Alwashali](https://hackdefendlabs.com/analysis/A-Tour-Inside-a-SOC-Analyst-Mind/)
 - [Anton’s Alert Fatigue: The Study](https://medium.com/anton-on-security/antons-alert-fatigue-the-study-0ac0e6f5621c)

### Newsletters
- [Last Week in Security (LWiS)](https://subscribe.badsectorlabs.com/subscription/form)
- [CyberWeekly](https://cyberweekly.substack.com/)
- [tl;dr sec](https://tldrsec.com/)

### Podcasts
- [Darknet Diaries](https://darknetdiaries.com/) - True stories from the dark side of the Internet.

### Books
- [Blue Team Handbook: SOC, SIEM, and Threat Hunting](https://www.amazon.com/Blue-Team-Handbook-Condensed-Operations/dp/1091493898)
- [Blue Team Handbook: Incident Response Edition](https://www.amazon.com/Blue-Team-Handbook-condensed-Responder/dp/1500734756)
- [Effective Threat Investigation for SOC Analysts: The ultimate guide to examining various threats and attacker techniques using security logs](https://www.packtpub.com/en-gr/product/effective-threat-investigation-for-soc-analysts-9781837634781)
- [BTFM: Blue Team Field Manual](https://www.amazon.com/Blue-Team-Field-Manual-BTFM/dp/154101636X)

### Training and Certifications
- [Blue Team Labs Online](https://blueteamlabs.online/) - A gamified platform for defenders to practice their skills in security investigations and challenges covering; Incident Response, Digital Forensics, Security Operations, Reverse Engineering, and Threat Hunting.
- [The DFIR Labs](https://thedfirreport.com/services/dfir-labs/) - Cloud-based DFIR Labs offer a hands-on learning experience, using real data from real intrusions. 
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
- [CyberDefenders CCD](https://cyberdefenders.org/blue-team-training/courses/certified-cyberdefender-certification/)
- [SANS SEC401: Security Essentials - Network, Endpoint, and Cloud](https://www.sans.org/cyber-security-courses/security-essentials-network-endpoint-cloud/)
- [SANS SEC450: Blue Team Fundamentals: Security Operations and Analysis](https://www.sans.org/cyber-security-courses/blue-team-fundamentals-security-operations-analysis/)
- [SANS SEC504: Hacker Tools, Techniques, and Incident Handling](https://www.sans.org/cyber-security-courses/hacker-techniques-incident-handling/)
- [OffSec SOC-200: Foundational Security Operations and Defensive Analysis](https://www.offsec.com/courses/soc-200/)
- [TCM Security Practical SOC Analyst Associate](https://certifications.tcm-sec.com/psaa/)
- [CompTIA CySA+](https://www.comptia.org/certifications/cybersecurity-analyst)
- [CompTIA Security+](https://www.comptia.org/certifications/security)
- [EC-Council Certified SOC Analyst](https://iclass.eccouncil.org/our-courses/certified-soc-analyst-csa)
- [EC-Council Certified Incident Handler](https://iclass.eccouncil.org/our-courses/certified-incident-handler-ecih/)

### Twitter/X
- [TheDFIRReport](https://x.com/TheDFIRReport)
- [Unit42](https://x.com/Unit42_Intel)
- [malwrhunterteam](https://x.com/malwrhunterteam)
- [abuse_ch](https://x.com/abuse_ch)
- [elasticseclabs](https://x.com/elasticseclabs)
- [nextronresearch](https://x.com/nextronresearch)
- [TheHackersNews](https://x.com/TheHackersNews)
- [BleepinComputer](https://x.com/BleepinComputer)
- [DarkWebInformer](https://x.com/DarkWebInformer)
- [malwrhunterteam](https://x.com/malwrhunterteam)
- [vxunderground](https://x.com/vxunderground)
- [Cryptolaemus1](https://x.com/Cryptolaemus1)
- [SOC List](https://x.com/i/lists/1903760692731056442)

### Interview Questions
- [SOC Interview Questions | LetsDefend](https://github.com/LetsDefend/SOC-Interview-Questions)
- [Interview Questions | socinvestigation.com](https://www.socinvestigation.com/soc-interview-questions-and-answers-cyber-security-analyst/)
- [SOC Interview Questions | siemxpert.com](https://www.siemxpert.com/blog/soc-analyst-interview-question/)

### Tools

#### Sandboxes
- [VirusTotal](https://www.virustotal.com/gui/home/search) - Analyze suspicious files, domains, IPs and URLs to detect malware and other breaches.
- [Hybrid Analysis](https://www.hybrid-analysis.com/) - Free malware analysis service for the community that detects and analyzes unknown threats.
- [AnyRun](https://app.any.run/) - Interactive malware analysis sandbox.
- [Triage | Recorded Future ](https://tria.ge/s) -  Malware analysis sandbox.
- [JOE Sandbox Cloud Basic](https://www.joesandbox.com/#windows) -  Malware analysis sandbox.
- [Threat Zone](https://app.threat.zone/scan) - Holistic malware analysis platform - interactive sandbox, static analyzer, emulation, URL Analyzer.
- [Filescan.io](https://www.filescan.io/scan) - Insightful Malware Analysis Powered by Emulation.
- [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) - Engine powered by ReversingLabs Titanium Platform
- [DOGGuard](https://app.docguard.io/) - Analyze files, Hashes and URLs.
- [Kaspersky Threat Intelligence Portal](https://opentip.kaspersky.com/?tab=upload) - Kaspersky file analysis.

#### IOC Lookups
- [VirusTotal | IP, Domain, URL, Hash](https://www.virustotal.com/#/home/search)
- [Cisco Talos Intelligence | IP, URL, Domain, Hash](https://talosintelligence.com/)
- [AbuseIPDB | IP, Subnet, Domain](https://www.abuseipdb.com/)
- [SpamHaus | IP, Domain, ASN, SBL, Email, Hash](https://check.spamhaus.org/)
- [MalwareBazaar | Hash](https://bazaar.abuse.ch/browse/)
- [URLHaus | Domain, URL, Hash](https://urlhaus.abuse.ch/browse/)
- [IBM X-Force Exchange | IP, URL, Hash](https://exchange.xforce.ibmcloud.com/)
- [ThreatFox IOC Database | IP, Domain, URL, Hash](https://threatfox.abuse.ch/browse/)
- [GreyNoise | IP](https://viz.greynoise.io/)
- [Pulsedive | IP, URL, Domain](https://pulsedive.com/analyze/)
- [threatbook | IP, Domain](https://threatbook.io/)
- [FortiGuard Labs | IP, Domain, URL](https://www.fortiguard.com/search)
- [Spamhaus IP Reputation | IP](https://www.spamhaus.org/ip-reputation/)
- [Spamhaus Domain Reputation | Domain](https://www.spamhaus.org/domain-reputation/)
- [Palo Alto URL | URL](https://urlfiltering.paloaltonetworks.com/query/)
- [DOGGuard | URL, Hash](https://app.docguard.io/)
- [AlienVault | IP, Domain, URL, Hash, FilePath, Email](https://otx.alienvault.com)
- [Kaspersky Threat Intelligence Portal | Hash, IP, Domain, URL](https://opentip.kaspersky.com/?tab=lookup)
- [Tor Metrics - ExoneraTor | IP (Tor network)](https://metrics.torproject.org/exonerator.html)
- [Tor Metrics - Relay Search | IP (Tor relay)](https://metrics.torproject.org/rs.html#search)

#### Emails
- [MXToolbox Emails| DMARC, SPF, DKIM, Header Analyzer](https://mxtoolbox.com/NetworkTools.aspx?tab=Email)

#### Multifunctional LookUp Services
- [IPVoid](https://www.ipvoid.com/)
- [MXToolbox](https://mxtoolbox.com/)
- [HackerTarget](https://hackertarget.com/)
- [ViewDNS](https://viewdns.info/)
- [IPduh](https://ipduh.com/)
- [SPUR](https://spur.us)

#### Fingerprinting
 - [Censys](https://search.censys.io/)
 - [Shodan](https://www.shodan.io/)
 - [ZoomEye](https://www.zoomeye.ai/)
 - [Onyphe](https://search.onyphe.io/)
 - [FOFA](https://en.fofa.info/)

#### Network Scanning
 - [MXToolbox Network Tools](https://mxtoolbox.com/NetworkTools.aspx?tab=Network)
 - [MXToolbox TCP Port Scan](https://mxtoolbox.com/TCPLookup.aspx)
 - [MXToolbox Ping](https://mxtoolbox.com/PingLookup.aspx)
 - [MXToolbox Traceroute](https://mxtoolbox.com/TraceRouteLookup.aspx)
 - [HackerTarget](https://hackertarget.com/)
 - [HackerTarget Nmap Scanner](https://hackertarget.com/nmap-online-port-scanner/)
 - [HackerTarget TCP Port Scan](https://hackertarget.com/tcp-port-scan/)
 - [HackerTarget UDP Port Scan](https://hackertarget.com/udp-port-scan/)
 - [HackerTarget Ping](https://hackertarget.com/test-ping/)
 - [HackerTarget Traceroute](https://hackertarget.com/online-traceroute/)
 - [DNSChecker Port Scanner](https://dnschecker.org/port-scanner.php)

#### SSL/TLS
- [HackerTarget SSL Check](https://hackertarget.com/ssl-check/)

#### Website Scan
 - [HackerTarget Whatweb/Wappalyzer Scan](https://hackertarget.com/whatweb-scan/) - Website technology analyzer.
 - [HackerTarget Dump Links](https://hackertarget.com/extract-links/) - Dump links from a website.

#### CMS Scan
- [HackerTarget Wordpress Scan](https://hackertarget.com/wordpress-security-scan/)
- [HackerTarget Joomla Scan](https://hackertarget.com/joomla-security-scan/)
- [HackerTarget Drupal Scan](https://hackertarget.com/drupal-security-scan/)

#### URL
- [VirusTotal](https://www.virustotal.com/#/home/search) - Scans provided URLs.
- [urlscan.io](https://urlscan.io/) - Page source code, requests analysis.
- [Cloudflare Radar URL Scan](https://radar.cloudflare.com/scan) - Gives you information about cookies, technology used, SSL certificates, headers and dns records and other.
- [URLVoid](https://www.urlvoid.com/) - Reputation check.
- [URLQuery](https://urlquery.net/search) -  Very nice analysis of the the scanned URL along with reputation check.
- [CyberGordon](https://cybergordon.com/) - Multiple engines scan.
- [Tiny Scan](https://www.tiny-scan.com/) - Gives you information about cookies, technology used, SSL certificates, headers and dns records and other.
- [CheckPhish](https://checkphish.bolster.ai/) - Check if URL is phishing.
- [PhishTank](https://phishtank.org/) - Check if URL is phishing.
- [HTTPStatus.io](https://httpstatus.io/) - Check URLs.
- [Redirect Checker](https://redirect-checker.net/) - Shows redirects.

#### DNS
 - [MXToolbox DNS Tools](https://mxtoolbox.com/NetworkTools.aspx?tab=DNS) - MXToolbox DNS tools.
 - [DNSChecker DNS Tools](https://dnschecker.org/all-tools.php#dnsTool) - DNSChecker DNS Tools.
 - [IPVoid Dig Lookup](https://www.ipvoid.com/dig-dns-lookup/) - Dig DNS Lookup.
 - [DNS Dumpster](https://dnsdumpster.com/) - DNS records.
 - [DNS History](https://dnshistory.org/) - Historical DNS records.

#### MAC
- [macaddress.io](https://macaddress.io) - Information about manufacturers.
- [macvendors.com](https://macvendors.com) - Information about manufacturers.
- [DNS Checker MAC Lookup](https://dnschecker.org/mac-lookup.php) - Information about manufacturers.

#### ASN
 - [ASN LookUp](https://asnlookup.com/)
 - [HackerTarget ASN Lookup](https://hackertarget.com/as-ip-lookup/)
 - [MXToolbox ASN Lookup](https://mxtoolbox.com/asn.aspx)

#### Browser Extension
- [CRXaminer](https://crxaminer.tech/) - Chrome extension analyzer.

#### User Agent
- [WhatMyUserAgent](https://whatmyuseragent.com/)
- [WhatIsMyBrowser](https://explore.whatismybrowser.com/useragents/parse/)

#### USB and PCI
 - [DeviceHunt](https://devicehunt.com/) - Find your device & driver from a massive database of PCI and USB devices.

#### EXE Lookup
- [XCyclopedia](https://strontic.github.io/xcyclopedia/index) - Look up information about known exe files - hashes, known paths, metadata, other.

#### Certificate
- [crt.sh](https://crt.sh/) - Certificate Search

#### Hash
 - [Hash Calculator](https://md5calc.com/hash) - Calculator for hashes.
 - [Hash Crack](https://crackstation.net/) - Cracking hashes online.

#### Misc Tools
 - [WayBack Machine](https://web.archive.org/) - Historical search of pages.
 - [RedHunt Labs Online Paste Tools Lookup](https://redhuntlabs.com/online-ide-search/) - Lookup keywords on online paste sites like pastebin.
 - [de4js](https://lelinhtinh.github.io/de4js/) - JavaScript Deobfuscator and Unpacker.
 - [deobfuscate.relative.im](https://deobfuscate.relative.im/) - JavaScript Deobfuscator.
 - [A-Packets PCAP Analyzer](https://apackets.com/) - PCAP analyzer from A-Packets.
 - [URLEncoder](https://www.urlencoder.org/) - URL encoder and decoder.
 - [explainshell.com](https://explainshell.com/) - Write down a command-line to see the help text that matches each argument
 - [Crontab Guru](https://crontab.guru) - The quick and simple editor for cron schedule expressions.
 - [MXToolbox Subnet Calculator](https://mxtoolbox.com/subnetcalculator.aspx) -  Enter a subnet range (CIDR) and see IP address information about that range.
 - [EpochConverter](https://www.epochconverter.com/) - Epoch & Unix Timestamp Conversion Tools.
 - [10 minute mail](https://10minutemail.com/) - Can be used for registrations.

#### Data Manipulation Online Tools
 - [Regex101](https://regex101.com/) - Regex testing.
 - [Regexr](https://regexr.com/) - Regex testing.
 - [CyberChef](https://gchq.github.io/CyberChef/) - Multiple data manipulation tools, decoders, decryptors.
 - [JSON Formatter](https://jsonformatter.curiousconcept.com/#) - JSON Beautifier.
 - [JSONCrack](https://jsoncrack.com/editor) - JSON, YML, CSV, XML Editor.
 - [Text Mechanic](https://textmechanic.com/) - Text manipulation  (Remove duplicates, prefix, suffix, word count etc.).
 - [Text Fixer](https://www.textfixer.com/) - Text manipulation (Remove duplicates, prefix, suffix, word count etc.).
 - [Free Formatter](https://www.freeformatter.com/xml-formatter.html) - Formatter for XML, JSON, HTML.
 - [Diff Checker](https://www.diffchecker.com/) - Diff comparison.
 - [ChatGPT](https://chatgpt.com/) - Can be used to transform data.
