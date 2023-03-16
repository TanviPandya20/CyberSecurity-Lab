# <p align="center"> Kali Tools </p>
-------------------------
# 1. Information Gethering
## A. DNS Analysis
### i. dnsenum
- Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations: Get the host's addresses (A record).
### ii. dnsrecon
DNSRecon is a Python script that provides the ability to perform:
- Check all NS Records for Zone Transfers.
- Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT).
- Perform common SRV Record Enumeration.
- Top Level Domain (TLD) Expansion.
- Check for Wildcard Resolution.
### iii. fierce
## B. IPS/IDS Identification
### i. ibd
### ii. Wafw00f
## C. Live host identification
### i. arping
### ii. fping
### iii. hping3
## D. Network and Port Scanners
### i. masscan
### ii. nmap
- Nmap is a utility for network exploration or security auditing. It supports ping scanning (determine which hosts are up), many port scanning techniques, version detection (determine service protocols and application versions listening behind ports), and TCP/IP fingerprinting (remote host OS or device identification).
## E. OSINT analysis
### i. spiderfoot
### ii. spiderfoot cli
### iii. theharvester
## F. Route Analysis
### i. netdiscover
### ii. netmask
## G. SMB Analysis
### i. enum4linux
### ii. nbtscan
### iii. smbmap
## H. SMTP Analysis
### i. swakes
## I. SMNP Analysis
### i. onesixtyone
### ii. snmp-check
## J. SSL Analysis
### i. ssldump
### ii. sslh
### iii. sslscan
## K. Amass
## L. Dmitry
## M. ike-scan
## N. legion(root)
- This package contains an open source, easy-to-use, super-extensible and semi-automated network penetration testing tool that aids in discovery, reconnaissance and exploitation of information systems. Legion is a fork of SECFORCE's Sparta.
## O. maltego(installer)
- What is the use of Maltego in Kali Linux?
Maltego is an open source intelligence and forensics application. It will offer you timous mining and gathering of information as well as the representation of this information in a easy to understand format. This package replaces previous packages matlegoce and casefile.
## P. netdiscover
## Q. nmap
- Nmap is a utility for network exploration or security auditing. It supports ping scanning (determine which hosts are up), many port scanning techniques, version detection (determine service protocols and application versions listening behind ports), and TCP/IP fingerprinting (remote host OS or device identification).
## R. recon-ng
## S. spiderfoot
# 2. Vulnarebility Analysis
## A. Fuzzing Tools
### i. spike- generic_listen_tcp
### ii. spike- generic_send_tcp
### iii. spike- generic_send_udp
## B. VoIP tools
### i. voiphopper
## C. Legion
- This package contains an open source, easy-to-use, super-extensible and semi-automated network penetration testing tool that aids in discovery, reconnaissance and exploitation of information systems. Legion is a fork of SECFORCE's Sparta.
## D. nikto
- What is use for Nikto in Kali Linux?
Image result for nikto use in kali linux
Nikto is a pluggable web server and CGI scanner written in Perl, using rfp's LibWhisker to perform fast security or informational checks. Features: Easily updatable CSV-format checks database. Output reports in plain text or HTML.
## E. nmap
## F. unix-privesc-check
# 3. Web application analysis
## A. CMS and framework identification
### i. WPscan
## B. Web application proxies
### i. Burpsuite
- Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities.
## C. Web crawlers & directory bruteforce
### i. dirb
### ii. ffuf
### iii. wfuzz
## D. Web vulnerability scanners
### i. Cadaver
### ii. whatweb
### iii. davtest
## E. Burpsuite
- Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities.
## F. Commix
## G. Skipfish
## H. SQLmap
- SQLMap is a tool used for the automated exploitation of SQL injection vulnerabilities. We can use SQLMap to test websites and databases for vulnerabilities and exploit those vulnerabilities to take over the database. To use SQLMap, we first need to identify a website or database that is vulnerable to SQL injection.
## I. WPscan
# 4. Database assessment
## A. SQLite database browser
## B. SQLmap
- SQLMap is a tool used for the automated exploitation of SQL injection vulnerabilities. We can use SQLMap to test websites and databases for vulnerabilities and exploit those vulnerabilities to take over the database. To use SQLMap, we first need to identify a website or database that is vulnerable to SQL injection.
# 5. Password attacks
## A. offline attacks
### i. hashcat
### ii. hashid
### iii. hash-identifier
## B. online attacks
### i. hydra
### ii. hydra graphical
### iii. pratator
## C. passing the hash tools
### i. smbmaps
### ii. mimikatz
### iii. pth-curl
## D. password profiling and wordlists
### i. Cewl
### ii. Crunch
### iii. rsmengler
## E. cewl
## F. crunch
## G. hashcat
## H. john
## I. medusa
## J. ncrack
## K. Ophcrack
## L. wordlists
# 6. Wireless Attacks
## A. 802.11 wireless tools
### i.bully
### ii. fern wifi cracker(root)
## B. Bluetooth tools
### i. spooftooph
## C. aircrack-ng
## D. fernwifi cracker(root)
## E. kismet
## F. pixiwps
## G. reaver
## H. wifite
# 7. Reverse Engineering
## A. clang 
## B. clang++
## C. radare2
## D. NASMshell
# 8. Expoitation tools
## A. crackmapexec
## B. metasploit framework
## C. msf payload creator
## D. searchsploit
## E. social engineering toolkit(root)
## F. SQLmap
- SQLMap is a tool used for the automated exploitation of SQL injection vulnerabilities. We can use SQLMap to test websites and databases for vulnerabilities and exploit those vulnerabilities to take over the database. To use SQLMap, we first need to identify a website or database that is vulnerable to SQL injection.
# 9. Sniffing & Spoofing
## A. Network sniffers
### i. dnschef
### ii. netsniff-ng
## B. spoofing and MITM
### i. dnschef
### ii. rebind
### iii. tcpreplay
## C. ettercap - graphical
## D. macchanger
## E. minicom
## F. mitmproxy
## G. netsniff-ng
## H. Responder
## I. Wireshark
# 10. post Exploitation
## A. OS backdoors
### i. dbd
### ii. powersploit
### iii. sbd
## B. Tunneling and exfilteration
### i. dbd
### ii. dns2tcpc
### iii. dns2tcpd
## C. Web backdoor
### i. laudanum
### ii. weevely
## D. evil-winrm
## E. exe2hex
## F. impacket
## G. mimikatz
## H. powershell empire
## I. powersploit
## J. proxychains4
## K. weevely
# 11. Forensics
## A. Forensic carving tools
### i. magicrescue
### ii. scalepel
### iii. scrounge-ntfs
## B. Forensic imaging tools
### i. guymager(root)
## C. PDF Forensic tools
### i. pdfid
### ii. pdfparser
## D. Seluth kit suite
### i. blkcalc
### ii. blkls
### iii. blkstat
## E. Autopsy (root)
## F. Binwalk
## G. Bulk_extractor
## H. Hashdeep
# 12. Reporting tools
## A. Cutycapt
## B. Faraday start
## C. Maltego(installer)
## D. Pipal
# 13. Social Engineering tools
## A. Maltego(installer)
## B. msf Payload creater
## C. Social Engineering toolkit(root)
