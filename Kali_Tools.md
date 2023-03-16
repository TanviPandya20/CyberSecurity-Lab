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
- Checks if a given domain uses load-balancing.
### ii. Wafw00f
This package identifies and fingerprints Web Application Firewall (WAF) products using the following logic:

- Sends a normal HTTP request and analyses the response; this identifies a number of WAF solutions.
- If that is not successful, it sends a number of (potentially malicious) HTTP requests and uses simple logic to deduce which WAF it is.
- If that is also not successful, it analyses the responses previously returned and uses another simple algorithm to guess if a WAF or security solution is actively responding to the attacks.
## C. Network and Port Scanners
### i. masscan
- MASSCAN is TCP port scanner which transmits SYN packets asynchronously and produces results similar to nmap, the most famous port scanner. 
- Internally, it operates more like scanrand, unicornscan, and ZMap, using asynchronous transmission. It's a flexible utility that allows arbitrary address and port ranges.
### ii. nmap
- Nmap is a utility for network exploration or security auditing. 
- It supports ping scanning (determine which hosts are up), many port scanning techniques, version detection (determine service protocols and application versions listening behind ports), and TCP/IP fingerprinting (remote host OS or device identification). 
- Nmap also offers flexible target and port specification, decoy/stealth scanning, sunRPC scanning, and more. Most Unix and Windows platforms are supported in both GUI and commandline modes. 
- Several popular handheld devices are also supported, including the Sharp Zaurus and the iPAQ.
## D. legion(root)
- This package contains an open source, easy-to-use, super-extensible and semi-automated network penetration testing tool that aids in discovery, reconnaissance and exploitation of information systems. Legion is a fork of SECFORCE's Sparta.
## E. maltego(installer)
- Maltego is an open source intelligence and forensics application. 
- It will offer you timous mining and gathering of information as well as the representation of this information in a easy to understand format.
- This package replaces previous packages matlegoce and casefile.
## F. netdiscover
- Netdiscover is an active/passive address reconnaissance tool, mainly developed for those wireless networks without dhcp server, when you are wardriving. 
- It can be also used on hub/switched networks.
## G. nmap
- Nmap is a utility for network exploration or security auditing. 
- It supports ping scanning (determine which hosts are up), many port scanning techniques, version detection (determine service protocols and application versions listening behind ports), and TCP/IP fingerprinting (remote host OS or device identification). 
- Nmap also offers flexible target and port specification, decoy/stealth scanning, sunRPC scanning, and more. Most Unix and Windows platforms are supported in both GUI and commandline modes. 
- Several popular handheld devices are also supported, including the Sharp Zaurus and the iPAQ.
## H. recon-ng
- Recon-ng is Open-Source Intelligence, the simplest and most useful reconnaissance tool. 
- Recon-ng UI is fairly similar to that of Metasploit 1 and Metasploit 2. On Kali Linux, Recon-ng provides a command-line interface that we can run on Kali Linux. - -- This tool can be used to collect data on our target (domain).
## I. spiderfoot
- This package contains an open source intelligence (OSINT) automation tool. 
- Its goal is to automate the process of gathering intelligence about a given target, which may be an IP address, domain name, hostname, network subnet, ASN, e-mail address or person's name.

# 2. Vulnarebility Analysis
## A. Fuzzing Tools
### i. spike- generic_listen_tcp
- When you need to analyze a new network protocol for buffer overflows or similar weaknesses, the SPIKE is the tool of choice for professionals. While it requires a strong knowledge of C to use, it produces results second to none in the field.
## B. VoIP tools
### i. voiphopper
- VoIP Hopper is a GPLv3 licensed security tool, written in C that rapidly runs a VLAN Hop security test. VoIP Hopper is a VoIP infrastructure security testing tool but also a tool that can be used to test the (in)security of VLANs. Dependencies: libc6.
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
- Unix-privesc-checker is a script that runs on Unix systems (tested on Solaris 9, HPUX 11, Various Linuxes, FreeBSD 6.2). 
- It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases).

# 3. Web application analysis
## A. CMS and framework identification
### i. WPscan
- WPScan is a very fast WordPress vulnerability scanner written in the Ruby programming language and preinstalled in Kali Linux. The following information can be extracted using WPScan: The plugins list. The name of the theme.
## B. Web application proxies
### i. Burpsuite
- Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities.
## D. Web vulnerability scanners
### i. Cadaver
## E. Burpsuite
- Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities.
## F. sqlmap
- sqlmap goal is to detect and take advantage of SQL injection vulnerabilities in web applications. 
- Once it detects one or more SQL injections on the target host, the user can choose among a variety of options to perform an extensive back-end database management system fingerprint, retrieve DBMS session user and database, enumerate users, password hashes, privileges, databases, dump entire or user’s specific DBMS tables/columns, run his own SQL statement, read specific files on the file system and more.
## G. WPscan
- WPScan is a very fast WordPress vulnerability scanner written in the Ruby programming language and preinstalled in Kali Linux. The following information can be extracted using WPScan: The plugins list. The name of the theme.

# 4. Database assessment
## A. SQLite database browser
- SQLite Database Browser is a visual tool used to create, design and edit database files compatible with SQLite. Its interface is based on QT, and is meant to be used for users and developers that want to create databases, edit and search data using a familiar spreadsheet-like interface, without the need to learn complicated SQL commands. 
## B. sqlmap
- sqlmap goal is to detect and take advantage of SQL injection vulnerabilities in web applications. 
- Once it detects one or more SQL injections on the target host, the user can choose among a variety of options to perform an extensive back-end database management system fingerprint, retrieve DBMS session user and database, enumerate users, password hashes, privileges, databases, dump entire or user’s specific DBMS tables/columns, run his own SQL statement, read specific files on the file system and more.

# 5. Password attacks
## A. offline attacks
### i. hashcat
- Hashcat supports five unique modes of attack for over 300 highly-optimized hashing algorithms. hashcat currently supports CPUs, GPUs, and other hardware accelerators on Linux, and has facilities to help enable distributed password cracking.
## B. online attacks
### i. hydra
- Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.
- This tool makes it possible for researchers and security consultants to show how easy it would be to gain unauthorized access to a system remotely.
### ii. hydra graphical
- Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.
- This tool makes it possible for researchers and security consultants to show how easy it would be to gain unauthorized access to a system remotely.
- This package provides the GTK+ based GUI for hydra.
### iii. pratator
- Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage. 
- Currently it supports the following modules: ftp_login : Brute-force FTP. ssh_login : Brute-force SSH.
## C. passing the hash tools
### i. smbmaps
- SMBMap allows users to enumerate samba share drives across an entire domain. 
- List share drives, drive permissions, share contents, upload/download functionality, file name auto-download pattern matching, and even execute remote commands.
## D. password profiling and wordlists
### i. john
- John the Ripper is a tool designed to help systems administrators to find weak (easy to guess or crack through brute force) passwords, and even automatically mail users warning them about it, if it is desired.
- Besides several crypt(3) password hash types most commonly found on various Unix flavors, supported out of the box are Kerberos AFS and Windows NT/2000/XP/2003 LM hashes, plus several more with contributed patches.
### ii. medusa
- Medusa is intended to be a speedy, massively parallel, modular, login brute-forcer. 
- The goal is to support as many services which allow remote authentication as possible. 
- The author considers following items as some of the key features of this application: * Thread-based parallel testing. 
- Brute-force testing can be performed against multiple hosts, users or passwords concurrently. * Flexible user input. Target information (host/user/password) can be specified in a variety of ways. For example, each item can be either a single entry or a file containing multiple entries. 
- Additionally, a combination file format allows the user to refine their target listing. * Modular design. Each service module exists as an independent .mod file.
- This means that no modifications are necessary to the core application in order to extend the supported list of services for brute-forcing.

# 6. Wireless Attacks
## A. 802.11 wireless tools
### i.bully
- Bully is a new implementation of the WPS brute force attack, written in C. It is conceptually identical to other programs, in that it exploits the (now well known) design flaw in the WPS specification. 
- It has several advantages over the original reaver code. These include fewer dependencies, improved memory and cpu performance, correct handling of endianness, and a more robust set of options.
## B. Bluetooth tools
### i. spooftooph
- Spooftooph is designed to automate spoofing or cloning Bluetooth device Name, Class, and Address. Cloning this information effectively allows Bluetooth device to hide in plain site.
## C. aircrack-ng
- aircrack-ng is an 802.11a/b/g WEP/WPA cracking program that can recover a 40-bit, 104-bit, 256-bit or 512-bit WEP key once enough encrypted packets have been gathered. 
- Also it can attack WPA1/2 networks with some advanced methods or simply by brute force.
- It implements the standard FMS attack along with some optimizations, thus making the attack much faster compared to other WEP cracking tools. 
- It can also fully use a multiprocessor system to its full power in order to speed up the cracking process.
- Aircrack-ng is a fork of aircrack, as that project has been stopped by the upstream maintainer.
## D. fernwifi cracker(root)
- This package contains a Wireless security auditing and attack software program written using the Python Programming Language and the Python Qt GUI library, the program is able to crack and recover WEP/WPA/WPS keys and also run other network based attacks on wireless or ethernet based networks.
## E. kismet
- Kismet is a wireless network and device detector, sniffer, wardriving tool, and WIDS (wireless intrusion detection) framework.
- Kismet works with Wi-Fi interfaces, Bluetooth interfaces, some SDR (software defined radio) hardware like the RTLSDR, and other specialized capture hardware.
- This is a metapackage containing the kismet tools.

# 7. Reverse Engineering
## A. clang 
- clang. Clang project is a C, C++, Objective C and Objective C++ front-end for the LLVM compiler. 
- Its goal is to offer a replacement to the GNU Compiler Collection (GCC). Clang implements all of the ISO C++ 1998, 11 and 14 standards and also provides most of the support of C++17.
## D. NASMshell
- Netwide Assembler. NASM will currently output flat-form binary files, a.out, COFF and ELF Unix object files, and Microsoft 16-bit DOS and Win32 object files.
- Also included is NDISASM, a prototype x86 binary-file disassembler which uses the same instruction table as NASM.
- NASM is released under the GNU Lesser General Public License (LGPL).

# 8. Expoitation tools
## A. crackmapexec
- This package is a swiss army knife for pentesting Windows/Active Directory environments.
- From enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL’s into memory using Powershell, dumping the NTDS.dit and more.
- The biggest improvements over the above tools are:
- Pure Python script, no external tools required
- Fully concurrent threading
- Uses ONLY native WinAPI calls for discovering sessions, users, dumping SAM hashes etc…
- Opsec safe (no binaries are uploaded to dump clear-text credentials, inject shellcode etc…)
Additionally, a database is used to store used/dumped credentals. It also automatically correlates Admin credentials to hosts and vice-versa allowing you to easily - - keep track of credential sets and gain additional situational awareness in large environments.
## B. metasploit framework
- One of the best sources of information on using the Metasploit Framework is Metasploit Unleashed, a free online course created by Offensive Security. 
- Metasploit Unleashed guides you from the absolute basics of Metasploit all the way through to advanced topics.
- The Metasploit Framework is an open source platform that supports vulnerability research, exploit development, and the creation of custom security tools.
## C. msf payload creator
- A quick way to generate various “basic” Meterpreter payloads using msfvenom which is part of the Metasploit framework.
## D. searchsploit
- Searchsploit is an offline tool, where you can easily search all kind of exploits in offline mode. 
- By using –help, you can easily see all the features and options which are available to you: Usage: To search the exploits of Linux Kernel 3.2, you can simply type this command: Command: searchsploit linux kernel 3.2.
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
- DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. 
- A DNS proxy (aka “Fake DNS”) is a tool used for application network traffic analysis among other uses.
### ii. netsniff-ng
- netsniff-ng is a high performance Linux network sniffer for packet inspection. It can be used for protocol analysis, reverse engineering or network debugging.
## B. spoofing and MITM
### i. dnschef
- DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. 
- A DNS proxy (aka “Fake DNS”) is a tool used for application network traffic analysis among other uses.
### ii. rebind
- Rebind is a tool that implements the multiple A record DNS rebinding attack. 
- Although this tool was originally written to target home routers, it can be used to target any public (non RFC1918) IP address.
- Rebind provides an external attacker access to a target router’s internal Web interface. 
- This tool works on routers that implement the weak end system model in their IP stack, have specifically configured firewall rules, and who bind their Web service to the router’s WAN interface. Note that remote administration does not need to be enabled for this attack to work. 
- All that is required is that a user inside the target network surf to a Web site that is controlled, or has been compromised, by the attacker.
### iii. tcpreplay
- Tcpreplay is aimed at testing the performance of a NIDS by replaying real background network traffic in which to hide attacks. Tcpreplay allows you to control the speed at which the traffic is replayed, and can replay arbitrary tcpdump traces.
## C. ettercap - graphical
- Ettercap supports active and passive dissection of many protocols (even encrypted ones) and includes many feature for network and host analysis. 
- Data injection in an established connection and filtering (substitute or drop a packet) on the fly is also possible, keeping the connection synchronized.
## D. macchanger
- GNU MAC Changer is an utility that makes the maniputation of MAC addresses of network interfaces easier. 
- MAC addresses are unique identifiers on networks, they only need to be unique, they can be changed on most network hardware. 
- MAC addresses have started to be abused by unscrupulous marketing firms, government agencies, and others to provide an easy way to track a computer across multiple networks. 
- By changing the MAC address regularly, this kind of tracking can be thwarted, or at least made a lot more difficult.
## E. minicom
- Minicom is a clone of the MS-DOS “Telix” communication program. It emulates ANSI and VT102 terminals, has a dialing directory and auto zmodem download.
## F. mitmproxy
- mitmproxy is an interactive man-in-the-middle proxy for HTTP and HTTPS. It provides a console interface that allows traffic flows to be inspected and edited on the fly.
Features:

- intercept and modify HTTP and HTTPS requests and responses and modify them on the fly
- save HTTP conversations for later replay and analysis
- replay the client-side of an HTTP conversation
- reverse proxy mode to forward traffic to a specified server
- transparent proxy mode on OSX and Linux
- make scripted changes to HTTP traffic using Python
- SSL/TLS certificates for interception are generated on the fly

This package contains the python-pathod module (previously provided by other source package). The python-netlib module was also included but it has been dropped by upstream in version 1.0.
## G. netsniff-ng
netsniff-ng toolkit currently consists of the following utilities:

- netsniff-ng: a zero-copy packet analyzer, pcap capturing/replaying tool
- trafgen: a multithreaded low-level zero-copy network packet generator
- mausezahn: high-level packet generator for appliances with Cisco-CLI
- ifpps: a top-like kernel networking and system statistics tool
- curvetun: a lightweight curve25519-based multiuser IP tunnel
- astraceroute: an autonomous system trace route and DPI testing utility
- flowtop: a top-like netfilter connection tracking tool
- bpfc: a [seccomp-]BPF (Berkeley packet filter) compiler, JIT disassembler
## H. Responder
- This package contains Responder/MultiRelay, an LLMNR, NBT-NS and MDNS poisoner. It will answer to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix 
- [](see: http://support.microsoft.com/kb/163409). 
- By default, the tool will only answer to File Server Service request, which is for SMB.
- The concept behind this is to target your answers, and be stealthier on the network. 
- This also helps to ensure that you don’t break legitimate NBT-NS behavior. You can set the -r option via command line if you want to answer to the Workstation Service request name suffix.
## I. Wireshark
- Wireshark is a network “sniffer” - a tool that captures and analyzes packets off the wire. 
- Wireshark can decode too many protocols to list here.
- This is a meta-package for Wireshark.

# 10. post Exploitation
## A. OS backdoors
### i. dbd
- dbd is a Netcat-clone, designed to be portable and offer strong encryption. 
- It runs on Unix-like operating systems and on Microsoft Win32. dbd features AES-CBC-128 + HMAC-SHA1 encryption (by Christophe Devine), program execution (-e option), choosing source port, continuous reconnection with delay, and some other nice features. 
- dbd supports TCP/IP communication only. Source code and binaries are distributed under the GNU General Public License.
### ii. powersploit
- PowerSploit is a series of Microsoft PowerShell scripts that can be used in post-exploitation scenarios during authorized penetration tests.
### iii. sbd
- sbd is a Netcat-clone, designed to be portable and offer strong encryption. 
- It runs on Unix-like operating systems and on Microsoft Win32. sbd features AES-CBC-128 + HMAC-SHA1 encryption (by Christophe Devine), program execution (-e option), choosing source port, continuous reconnection with delay, and some other nice features. 
- sbd supports TCP/IP communication only.
## B. Tunneling and exfilteration
### i. dbd
- dbd is a Netcat-clone, designed to be portable and offer strong encryption. 
- It runs on Unix-like operating systems and on Microsoft Win32. dbd features AES-CBC-128 + HMAC-SHA1 encryption (by Christophe Devine), program execution (-e option), choosing source port, continuous reconnection with delay, and some other nice features. 
- dbd supports TCP/IP communication only. Source code and binaries are distributed under the GNU General Public License.
### ii. dns2tcpc
- In this case we are going to tunnel some traffic from a client behind a perimeter firewall to our own server. 
- Since dns2tcp is using dns (asking for TXT records within a (sub)domain) to archive the goal we need to create a NS record for a new subdomain pointing to the address of our server.
- dns2tcp.kali.org. IN NS lab.kali.org.
- There is no need for a DNS server installation. But please keep in mind that you probably added a new NS to a real DNS zone. And it might take a while until the new subdomain is “active”.
### iii. dns2tcpd
- In the next step (dns2tcpd Usage Example) we create a configuration file on our server (lab.kali.org) and start the daemon. 
- To make sure everything is working well you should consider using the options “-F” (Run in foreground) and “-d 1” (debugging) at the first start.
## C. Web backdoor
### i. laudanum
- Laudanum is a collection of injectable files, designed to be used in a pentest when SQL injection flaws are found and are in multiple languages for different environments.They provide functionality such as shell, DNS query, LDAP retrieval and others.
### ii. weevely
- Weevely is a stealth PHP web shell that simulate telnet-like connection. 
- It is an essential tool for web application post exploitation, and can be used as stealth backdoor or as a web shell to manage legit web accounts, even free hosted ones.
## D. evil-winrm
- This package contains the ultimate WinRM shell for hacking/pentesting.
- WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. 
- A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.
- This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985), of course only if you have credentials and permissions to use it. So it could be used in a post-exploitation hacking/pentesting phase. 
- The purpose of this program is to provide nice and easy-to-use features for hacking. 
- It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
- It is using PSRP (Powershell Remoting Protocol) for initializing runspace pools as well as creating and processing pipelines.
## E. exe2hex
- A Python script to convert a Windows PE executable file to a batch file and vice versa.
## F. impacket
- Impacket is a collection of Python3 classes focused on providing access to network packets. 
- Impacket allows Python3 developers to craft and decode network packets in simple and consistent manner. 
- It includes support for low-level protocols such as IP, UDP and TCP, as well as higher-level protocols such as NMB and SMB.
- Impacket is highly effective when used in conjunction with a packet capture utility or package such as Pcapy. 
- Packets can be constructed from scratch, as well as parsed from raw data. Furthermore, the object oriented API makes it simple to work with deep protocol hierarchies.
## G. mimikatz
- Mimikatz uses admin rights on Windows to display passwords of currently logged in users in plaintext.
## H. powershell empire
- This package contains a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python Linux/OS X agent. 
- It is the merge of the previous PowerShell Empire and Python EmPyre projects. 
- The framework offers cryptologically-secure communications and a flexible architecture. 
- On the PowerShell side, Empire implements the ability to run PowerShell agents without needing powershell.exe, rapidly deployable post-exploitation modules ranging from key loggers to Mimikatz, and adaptable communications to evade network detection, all wrapped up in a usability-focused framework.
## I. powersploit
- PowerSploit is a series of Microsoft PowerShell scripts that can be used in post-exploitation scenarios during authorized penetration tests.
## J. proxychains4
- Proxychains is a UNIX program, that hooks network-related libc functions in dynamically linked programs via a preloaded DLL (dlsym(), LD_PRELOAD) and redirects the connections through SOCKS4a/5 or HTTP proxies. 
- It supports TCP only (no UDP/ICMP etc).
- This project, proxychains-ng, is the continuation of the unmaintained proxychains project (known as proxychains package in Debian).
- This package provides the runtime shared library used by proxychains-ng program.
## K. weevely
- Weevely is a stealth PHP web shell that simulate telnet-like connection. 
- It is an essential tool for web application post exploitation, and can be used as stealth backdoor or as a web shell to manage legit web accounts, even free hosted ones.

# 11. Forensics
## A. Forensic carving tools
### i. magicrescue
- Magic Rescue scans a block device for file types it knows how to recover and calls an external program to extract them. 
- It looks at “magic bytes” (file patterns) in file contents, so it can be used both as an undelete utility and for recovering a corrupted drive or partition. As long as the file data is there, it will find it.
- Magic Rescue uses files called ‘recipes’. These files have strings and commands to identify and extract data from devices or forensics images. 
- So, you can write your own recipes. Currently, there are the following recipes: avi, canon-cr2, elf, flac, gpl, gzip, jpeg-exif, jpeg-jfif, mbox, mbox-mozilla-inbox, mbox-mozilla-sent, mp3-id3v1, mp3-id3v2, msoffice, nikon-raw, perl, png, ppm, sqlite and zip.
- This package provides magicrescue, dupemap and magicsort commands. magicrescue is a carver and it is useful in forensics investigations.
### ii. scalepel
- scalpel is a fast file carver that reads a database of header and footer definitions and extracts matching files from a set of image files or raw device files.
- scalpel is filesystem-independent and will carve files from FAT16, FAT32, exFAT, NTFS, Ext2, Ext3, Ext4, JFS, XFS, ReiserFS, raw partitions, etc.
- scalpel is a complete rewrite of the Foremost 0.69 file carver and is useful for both digital forensics investigations and file recovery.
### iii. scrounge-ntfs
- Scrounge NTFS is a data recovery program for NTFS filesystems. 
- It reads each block of the hard disk and try to rebuild the original filesystem tree into a directory.
- This package is useful in forensics investigations.
## B. Forensic imaging tools
### i. guymager(root)
- The forensic imager contained in this package, guymager, was designed to support different image file formats, to be most user-friendly and to run really fast. 
- It has a high speed multi-threaded engine using parallel compression for best performance on multi-processor and hyper-threading machines.
## C. PDF Forensic tools
### i. pdfid
- This tool is not a PDF parser, but it will scan a file to look for certain PDF keywords, allowing you to identify PDF documents that contain (for example) JavaScript or execute an action when opened. PDFiD will also handle name obfuscation.
### ii. pdfparser
- This tool will parse a PDF document to identify the fundamental elements used in the analyzed file. It will not render a PDF document.
## D. Seluth kit suite
- The Sleuth Kit, also known as TSK, is a collection of UNIX-based command line file and volume system forensic analysis tools. 
- The filesystem tools allow you to examine filesystems of a suspect computer in a non-intrusive fashion. Because the tools do not rely on the operating system to process the filesystems, deleted and hidden content is shown.
- The volume system (media management) tools allow you to examine the layout of disks and other media. You can also recover deleted files, get information stored in slack spaces, examine filesystems journal, see partitions layout on disks or images etc. 
- But is very important clarify that the TSK acts over the current filesystem only.
- The Sleuth Kit supports DOS partitions, BSD partitions (disk labels), Mac partitions, Sun slices (Volume Table of Contents), and GPT disks. 
- With these tools, you can identify where partitions are located and extract them so that they can be analyzed with filesystem analysis tools.

Currently, TSK supports several filesystems, as NTFS, FAT, exFAT, HFS+, Ext3, Ext4, UFS and YAFFS2.

This package contains the set of command line tools in The Sleuth Kit.
### i. blkcalc
- Converts between unallocated disk unit numbers and regular disk unit numbers.
### ii. blkls
- List or output file system data units.
### iii. blkstat
- Display details of a file system data unit (i.e. block or sector).
## E. Autopsy (root)
- The Autopsy Forensic Browser is a graphical interface to the command line digital forensic analysis tools in The Sleuth Kit. 
- Together, The Sleuth Kit and Autopsy provide many of the same features as commercial digital forensics tools for the analysis of Windows and UNIX file systems (NTFS, FAT, FFS, EXT2FS, and EXT3FS).
## F. Binwalk
- Binwalk is a tool for searching a given binary image for embedded files and executable code. Specifically, it is designed for identifying files and code embedded inside of firmware images. 
- Binwalk uses the libmagic library, so it is compatible with magic signatures created for the Unix file utility.
- Binwalk also includes a custom magic signature file which contains improved signatures for files that are commonly found in firmware images such as compressed/archived files, firmware headers, Linux kernels, bootloaders, filesystems, etc.
- This package is an empty package, because the binary tool is already provided with the library, dependency of this package.
## G. Bulk_extractor
- bulk_extractor is a C++ program that scans a disk image, a file, or a directory of files and extracts useful information without parsing the file system or file system structures. 
- The results are stored in feature files that can be easily inspected, parsed, or processed with automated tools. 
- bulk_extractor also creates histograms of features that it finds, as features that are more common tend to be more important.
## H. Hashdeep
hashdeep is a set of tools to compute MD5, SHA1, SHA256, tiger and whirlpool hashsums of arbitrary number of files recursively.
The main hashdeep features are:
- It can compare those hashsums with a list of known hashes;
- The tools can display those that match the list or those that does not match;
- It can display a time estimation when processing large files.
- It can do piecewise hashing (hash input files in arbitrary sized blocks).
- This package is useful in forensics investigations.

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
