# <p align="center"> Kali Tools </p>
-------------------------
# 1. Information Gethering
## A. DNS Analysis
### i. dnsenum
- Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. 
- The main purpose of Dnsenum is to gather as much information as possible about a domain. 
- The program currently performs the following operations: Get the host's addresses (A record).
### ii. dnsrecon
DNSRecon is a Python script that provides the ability to perform: 
- Check all NS Records for Zone Transfers.
- Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT).
- Perform common SRV Record Enumeration.
- Top Level Domain (TLD) Expansion.
- Check for Wildcard Resolution.
- Brute Force subdomain and host A and AAAA records given a domain and a wordlist.
- Perform a PTR Record lookup for a given IP Range or CIDR.
- Check a DNS Server Cached records for A, AAAA and CNAME
- Records provided a list of host records in a text file to check.
- Enumerate Hosts and Subdomains using Google
### iii. fierce
- Fierce is a semi-lightweight scanner that helps locate non-contiguous IP space and hostnames against specified domains. It's really meant as a pre-cursor to nmap, unicornscan, nessus, nikto, etc, since all of those require that you already know what IP space you are looking for.
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
- Nmap is a utility for network exploration or security auditing. 
- It supports ping scanning (determine which hosts are up), many port scanning techniques, version detection (determine service protocols and application versions listening behind ports), and TCP/IP fingerprinting (remote host OS or device identification). 
- Nmap also offers flexible target and port specification, decoy/stealth scanning, sunRPC scanning, and more. Most Unix and Windows platforms are supported in both GUI and commandline modes. 
- Several popular handheld devices are also supported, including the Sharp Zaurus and the iPAQ.
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
- Maltego is an open source intelligence and forensics application. 
- It will offer you timous mining and gathering of information as well as the representation of this information in a easy to understand format.
- This package replaces previous packages matlegoce and casefile.
## P. netdiscover
## Q. nmap
- Nmap is a utility for network exploration or security auditing. 
- It supports ping scanning (determine which hosts are up), many port scanning techniques, version detection (determine service protocols and application versions listening behind ports), and TCP/IP fingerprinting (remote host OS or device identification). 
- Nmap also offers flexible target and port specification, decoy/stealth scanning, sunRPC scanning, and more. Most Unix and Windows platforms are supported in both GUI and commandline modes. 
- Several popular handheld devices are also supported, including the Sharp Zaurus and the iPAQ.
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
- Nmap is a utility for network exploration or security auditing. 
- It supports ping scanning (determine which hosts are up), many port scanning techniques, version detection (determine service protocols and application versions listening behind ports), and TCP/IP fingerprinting (remote host OS or device identification). 
- Nmap also offers flexible target and port specification, decoy/stealth scanning, sunRPC scanning, and more. Most Unix and Windows platforms are supported in both GUI and commandline modes. 
- Several popular handheld devices are also supported, including the Sharp Zaurus and the iPAQ.
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
## H. sqlmap
- sqlmap goal is to detect and take advantage of SQL injection vulnerabilities in web applications. 
- Once it detects one or more SQL injections on the target host, the user can choose among a variety of options to perform an extensive back-end database management system fingerprint, retrieve DBMS session user and database, enumerate users, password hashes, privileges, databases, dump entire or user’s specific DBMS tables/columns, run his own SQL statement, read specific files on the file system and more.
## I. WPscan

# 4. Database assessment
## A. SQLite database browser
## B. sqlmap
- sqlmap goal is to detect and take advantage of SQL injection vulnerabilities in web applications. 
- Once it detects one or more SQL injections on the target host, the user can choose among a variety of options to perform an extensive back-end database management system fingerprint, retrieve DBMS session user and database, enumerate users, password hashes, privileges, databases, dump entire or user’s specific DBMS tables/columns, run his own SQL statement, read specific files on the file system and more.

# 5. Password attacks
## A. offline attacks
### i. hashcat
### ii. hashid
### iii. hash-identifier
## B. online attacks
### i. hydra
- Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.
- This tool makes it possible for researchers and security consultants to show how easy it would be to gain unauthorized access to a system remotely.
### ii. hydra graphical
- Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.
- This tool makes it possible for researchers and security consultants to show how easy it would be to gain unauthorized access to a system remotely.
- This package provides the GTK+ based GUI for hydra.
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
- John the Ripper is a tool designed to help systems administrators to find weak (easy to guess or crack through brute force) passwords, and even automatically mail users warning them about it, if it is desired.
- Besides several crypt(3) password hash types most commonly found on various Unix flavors, supported out of the box are Kerberos AFS and Windows NT/2000/XP/2003 LM hashes, plus several more with contributed patches.
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
- aircrack-ng is an 802.11a/b/g WEP/WPA cracking program that can recover a 40-bit, 104-bit, 256-bit or 512-bit WEP key once enough encrypted packets have been gathered. 
- Also it can attack WPA1/2 networks with some advanced methods or simply by brute force.
- It implements the standard FMS attack along with some optimizations, thus making the attack much faster compared to other WEP cracking tools. 
- It can also fully use a multiprocessor system to its full power in order to speed up the cracking process.
- Aircrack-ng is a fork of aircrack, as that project has been stopped by the upstream maintainer.
## D. fernwifi cracker(root)
## E. kismet
- Kismet is a wireless network and device detector, sniffer, wardriving tool, and WIDS (wireless intrusion detection) framework.
- Kismet works with Wi-Fi interfaces, Bluetooth interfaces, some SDR (software defined radio) hardware like the RTLSDR, and other specialized capture hardware.
- This is a metapackage containing the kismet tools.
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
- One of the best sources of information on using the Metasploit Framework is Metasploit Unleashed, a free online course created by Offensive Security. 
- Metasploit Unleashed guides you from the absolute basics of Metasploit all the way through to advanced topics.
- The Metasploit Framework is an open source platform that supports vulnerability research, exploit development, and the creation of custom security tools.
## C. msf payload creator
- A quick way to generate various “basic” Meterpreter payloads using msfvenom which is part of the Metasploit framework.
## D. searchsploit
## E. Social engineering toolkit(root)
- The Social-Engineer Toolkit (SET) is an open-source penetration testing framework designed for social engineering. 
- SET has a number of custom attack vectors that allow you to make a believable attack in a fraction of time. 
- These kind of tools use human behaviors to trick them to the attack vectors.
## F. sqlmap
- sqlmap goal is to detect and take advantage of SQL injection vulnerabilities in web applications. 
- Once it detects one or more SQL injections on the target host, the user can choose among a variety of options to perform an extensive back-end database management system fingerprint, retrieve DBMS session user and database, enumerate users, password hashes, privileges, databases, dump entire or user’s specific DBMS tables/columns, run his own SQL statement, read specific files on the file system and more.

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
- Wireshark is a network “sniffer” - a tool that captures and analyzes packets off the wire. 
- Wireshark can decode too many protocols to list here.
- This is a meta-package for Wireshark.

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
- CutyCapt is a small cross-platform command-line utility to capture WebKit's rendering of a web page into a variety of vector and bitmap formats, including SVG, PDF, PS, PNG, JPEG, TIFF, GIF, and BMP.
## B. Faraday start
- Faraday is a GUI application that consists of a ZSH terminal and a sidebar with details about your workspaces and hosts.
- When Faraday supports the command you are running, it will automatically detect it and import the results. 
- In the example below, the original nmap command that was entered was nmap -A 192.168.0.7, which Faraday converted on the fly.
## C. Maltego(installer)
- Maltego is an open source intelligence and forensics application. 
- It will offer you timous mining and gathering of information as well as the representation of this information in a easy to understand format.
- This package replaces previous packages matlegoce and casefile.
## D. Pipal
- All this tool does is to give you the stats and the information to help you analyse the passwords. The real work is done by you in interpreting the results.

# 13. Social Engineering tools
## A. Maltego(installer)
- Maltego is an open source intelligence and forensics application. 
- It will offer you timous mining and gathering of information as well as the representation of this information in a easy to understand format.
- This package replaces previous packages matlegoce and casefile.
## B. msf Payload creater
- A quick way to generate various “basic” Meterpreter payloads using msfvenom which is part of the Metasploit framework.
## C. Social Engineering toolkit(root)
- The Social-Engineer Toolkit (SET) is an open-source penetration testing framework designed for social engineering. 
- SET has a number of custom attack vectors that allow you to make a believable attack in a fraction of time. 
- These kind of tools use human behaviors to trick them to the attack vectors.
