# <p align="center">ZEEK</p>
## <p align="center">Introduction</p>
- Zeek (formerly Bro) is an open-source and commercial network monitoring tool (traffic analyser).
- "Zeek (formerly Bro) is the world's leading platform for network security monitoring. Flexible, open-source, and powered by defenders." "Zeek is a passive, open-source network traffic analyser. Many operators use Zeek as a network security monitor (NSM) to support suspicious or malicious activity investigations. Zeek also supports a wide range of traffic analysis tasks beyond the security domain, including performance measurement and troubleshooting."
- The room aims to provide a general network monitoring overview and work with Zeek to investigate captured traffic. This room will expect you to have basic Linux familiarity and Network fundamentals (ports, protocols and traffic data). 
# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/ab4ba276-9806-4a9b-a259-51e950084e3d)
</p>
- Exercise files are located in the folder on the desktop. Log cleaner script "clear-logs.sh" is available in each exercise folder.

## <p align="center">Network Security Monitoring and Zeek</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/0ade983f-ba1e-4c35-80c7-4fc9fa47eace)
</p>

### Introduction to Network Monitoring Approaches
- Network monitoring is highly focused on IT assets like uptime (availability), device health and connection quality (performance), and network traffic balance and management (configuration). Monitoring and visualising the network traffic, troubleshooting, and root cause analysis are also part of the Network Monitoring process. 

### Network Security Monitoring
- Network Security Monitoring is focused on network anomalies like rogue hosts, encrypted traffic, suspicious service and port usage, and malicious/suspicious traffic patterns in an intrusion/anomaly detection and response approach.
- Monitoring and visualising the network traffic and investigating suspicious events is a core part of Network Security Monitoring. This model is helpful for security analysts/incident responders, security engineers and threat hunters and covers identifying threats, vulnerabilities and security issues with a set of rules, signatures and patterns. 

### What is ZEEK?
- Zeek is supported by several developers, and Corelight provides an Enterprise-ready fork of Zeek. Therefore this tool is called both open source and commercial. 

### Zeek vs Snort
# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/735222a5-1caf-4b0c-945a-8fb39dfe8389)
</p>

### Zeek Architecture
# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/621487f3-f08a-4fa1-807a-cf904182e7ac)
</p>

- Zeek has two primary layers; "Event Engine" and "Policy Script Interpreter".
- The Event Engine layer is where the packets are processed; it is called the event core and is responsible for describing the event without focusing on event details. It is where the packages are divided into parts such as source and destination addresses, protocol identification, session analysis and file extraction.
- The Policy Script Interpreter layer is where the semantic analysis is conducted. It is responsible for describing the event correlations by using Zeek scripts.

### Zeek Frameworks
# <p align="center"> ![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/b82c20e7-9ae3-4d2c-bbdd-819d2bae5a9d)
</p>

### Zeek Outputs
- Once you run Zeek, it will automatically start investigating the traffic or the given pcap file and generate logs automatically.
- Once you process a pcap with Zeek, it will create the logs in the working directory. If you run the Zeek as a service, your logs will be located in the default log path.
- The default log path is: <b>/opt/zeek/logs/</b>

### Working with Zeek
# <p align="center"> ![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/9293ac8e-9c79-4c6f-b481-9d60e42dfd49)
</p>

# <p align="center"> ![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/a0ec0937-c39d-471d-bbb8-b3aaee6aabde)
</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/7e733750-d385-4191-9f6d-c15461b30674)
</p>

# <p align="center"> ![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/81688984-ee4c-43ab-9f97-a8dc82e20ca4)
</p>

## <p align="center">Zeek Logs</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/dc765b3c-388c-45ea-8712-a36ba6d7d5d1)
</p>
- Zeek generates log files according to the traffic data. You will have logs for every connection in the wire, including the application level protocols and fields. Zeek is capable of identifying 50+ logs and categorising them into seven categories.
- Each log output consists of multiple fields, and each field holds a different part of the traffic data. Correlation is done through a unique value called "UID". The "UID" represents the unique identifier assigned to each session.

### Zeek logs in a nutshell

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/1283ec67-0510-4914-b2e8-678697a95057)
</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/fdb2a676-6ce0-4e1f-9ef5-378eda9ac12f)
</p>

### Brief log usage primer table

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/00806b8d-9db9-464e-bda8-28340359a9e9)
</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/2dc3b658-5118-4a86-9604-e7e4eb330ec8)
</p>

- cat dns.log | zeek-cut -d ts id.orig_h id.resp_h query


# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/400bb186-0b88-42e1-8996-9c262e6c12d4)
</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/42f48392-87bf-4298-9bbf-e1a9d0c3a136)
</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/66de8d8b-3614-4781-b941-4a196296338e)</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/322a9a95-8425-485f-91a8-b6b7db0bec7d)</p>

## <p align="center">CLI Kung-Fu Recall: Processing Zeek Logs</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/e467348c-c0fd-4167-a6aa-a057c588c07c)
</p>

- Having the power to manipulate the data at the command line is a crucial skill for analysts. Not only in this room but each time you deal with packets, you will need to use command-line tools, Berkeley Packet Filters (BPF) and regular expressions to find/view/extract the data you are looking for. This task provides quick cheat-sheet like information to help you write CLI queries for your event of interest.

## <p align="center">Zeek Signatures</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/f32d9e96-0f22-492c-b02f-2a02dda0986d)
</p>

- Zeek supports signatures to have rules and event correlations to find noteworthy activities on the network.
- Zeek signatures use low-level pattern matching and cover conditions similar to Snort rules. Unlike Snort rules, Zeek rules are not the primary event detection point.
-  Zeek has a scripting language and can chain multiple events to find an event of interest.
-  
# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/1261ca77-fa47-4793-a80c-fee9f0fe9ff7)
</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/d37fcc4b-f235-4adc-b900-73912abffc21)
</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/03f649cf-1265-49f6-ba38-3c64cb9e2610)
</p>

### Example | Cleartext Submission of Password

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/4da9e54c-1977-43ba-aca3-82b1a27d3d85)
</p>

- Remember, Zeek signatures support regex. Regex ".*" matches any character zero or more times. The rule will match when a "password" phrase is detected in the packet payload. Once the match occurs, Zeek will generate an alert and create additional log files (signatures.log and notice.log).

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/0cb6a417-37d3-4b44-86e5-e4d2ea51bdc4)
</p>

- As shown in the above terminal output, the signatures.log and notice.log provide basic details and the signature message. Both of the logs also have the application banner field. So it is possible to know where the signature match occurs. Let's look at the application banner!

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/fcc677df-5df6-43fc-baeb-7d05cb1b394b)
</p>

- We will demonstrate only one log file output to avoid duplication after this point. You can practice discovering the event of interest by analysing notice.log and signatures.log.

### Example | FTP Brute-force

- Let's create another rule to filter FTP traffic. This time, we will use the FTP content filter to investigate command-line inputs of the FTP traffic. The aim is to detect FTP "admin" login attempts. This basic signature will help us identify the admin login attempts and have an idea of possible admin account abuse or compromise events.

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/7fbabaa7-9700-491c-92ee-79a9c0f4080f)
</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/cd346715-171b-48ec-a3ee-a5827f4489e7)
</p>

- Our rule shows us that there are multiple logging attempts with account names containing the "admin" phrase. The output gives us great information to notice if there is a brute-force attempt for an admin account.
- This signature can be considered a case signature. While it is accurate and works fine, we need global signatures to detect the "known threats/anomalies". We will need those case-based signatures for significant and sophistical anomalies like zero-days and insider attacks in the real-life environment. Having individual rules for each case will create dozens of logs and alerts and cause missing the real anomaly. The critical point is logging logically, not logging everything.

### Let's optimise our rule and make it detect all possible FTP brute-force attempts

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/49d5675c-aff1-4609-98b0-5d57e15956b6)
</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/c53cc00e-bbff-4d8a-9a4c-994f05c36282)
</p>

- This rule should show us two types of alerts and help us to correlate the events by having "FTP Username Input" and "FTP Brute-force Attempt" event messages. Let's investigate the logs. We're grepping the logs in range 1001-1004 to demonstrate that the first rule matches two different accounts (admin and administrator).

### Snort Rules in Zeek?
- While Zeek was known as Bro, it supported Snort rules with a script called snort2bro, which converted Snort rules to Bro signatures. However, after the rebranding, workflows between the two platforms have changed. The official Zeek document mentions that the script is no longer supported and is not a part of the Zeek distribution.

1.
 
# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/face62f3-bfe3-465e-bb9c-882f938fd4d7)
</p>

2. 
 
# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/202c42ab-a73e-4b8d-9cad-aa93a8d48db9)
</p>

3. 

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/05989a80-04d8-43be-a344-a7047c360743)
</p>

4.

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/69ba6b91-d76a-45e3-911c-7a4ad023df42)
</p>

5.

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/63938a2f-1511-481d-8400-901aa3f2bc3b)
</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/444b5e9d-1c4e-493c-8cf2-e06ae146d314)
</p>

6.

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/df78c3ec-db8e-4022-a725-9961ed7d7450)
</p>

## <p align="center">Zeek Scripts | Fundamentals</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/7f5d8060-1be1-4789-ae57-eb1798e1e19d)
</p>

- Zeek has its own event-driven scripting language, which is as powerful as high-level languages and allows us to investigate and correlate the detected events. Since it is as capable as high-level programming languages, you will need to spend time on Zeek scripting language in order to become proficient.
- In this room, we will cover the basics of Zeek scripting to help you understand, modify and create basic scripts. Note that scripts can be used to apply a policy and in this case, they are called policy scripts.

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/9166fb02-3d80-4f8b-8bb7-84cecc4d35ea)
</p>

2.
- zeek -C -r smallFlows.pcap dhcp-hostname.zeek
- cat dhcp.log
- A - astaro_vineyard

3.
- cat dhcp.log | zeek-cut host_name | sort -rn | uniq | wc -l
- A - 17

4.
- cat dhcp.log | zeek-cut domain
- A - jaalam.net

5.
- cat dns.log | zeek-cut query | grep -v -e’*’ -e’-’ | sort -rn | uniq | wc -l
- A - 1109

## <p align="center">Zeek Scripts | Scripts and Signatures</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/c36a0246-c45b-4f17-912c-54d259dfcae7)
</p>

- Scripts contain operators, types, attributes, declarations and statements, and directives. Let's look at a simple example event called "zeek_init" and "zeek_done". These events work once the Zeek process starts and stops. Note that these events don't have parameters, and some events will require parameters.

2.
- zeek -C -r sample.pcap 103.zeek | grep “New Connection Found”| wc -l
- A - 87

3.
- zeek -C -r ftp.pcap -s ftp-admin.sig 201.zeek
- cat signatures.log | grep “ftp-admin” | wc -l
- A - 1401

4.
- cat signatures.log | grep “administrator” | wc -l
- A - 731

5.
- zeek -C -r ftp.pcap local
- cat loaded_scripts.log | grep “.zeek” | wc -l
- A - 498

6.
- zeek -C -r ftp.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek
- A - 2

## <p align="center">Zeek Scripts | Frameworks</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/c7ad21cb-6caf-44dd-bac9-b9208f1436f2)
</p>

- Zeek has 15+ frameworks that help analysts to discover the different events of interest. In this task, we will cover the common frameworks and functions.
### File Framework | Hashes
### File Framework | Extract Files
### Notice Framework | Intelligence

2. 
- zeek -C -r case1.pcap intelligence-demo.zeek
- cat intel.log
- A - IN_HOST_HEADER

3.
- cat http.log | zeek-cut uri
- A - knr.exe

4.
- zeek -C -r case1.pcap hash-demo.zeek
- cat files.log | zeek-cut md5
- A - cc28e40b46237ab6d5282199ef78c464

5.
- zeek -C -r case1.pcap /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek
- ls extract_files | nl
- cd extract_files/
- cat The_Extract_File
- A - Microsoft NCSI


## <p align="center">Zeek Scripts | Packages</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/b2ff8024-4669-43a1-849d-7355a669f707)
</p>

- Zeek Package Manager helps users install third-party scripts and plugins to extend Zeek functionalities with ease. The package manager is installed with Zeek and available with the zkg command. Users can install, load, remove, update and create packages with the "zkg" tool.

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/00bf9465-bc79-4bb9-b2c5-fcdcb1c2aca5)
</p>

### Packages | Cleartext Submission of Password
### Packages | Geolocation Data 

2. 
- zeek -Cr http.pcap /opt/zeek/share/zeek/site/zeek-sniffpass
- A - brozeek

3. 
- zeek -Cr case2.pcap /opt/zeek/share/zeek/site/geoip-conn
- cat conn.log
- A - chicago

4. 
- A - 23.77.86.54

5. 
- zeek -Cr case2.pcap sumstats-counttable.zeek
- A - 4

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/6cf25193-ff6c-4dc1-8e2d-1e84fcba31d3)
</p>
  
# <p align="center">ZEEK Exercises</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/faffe67b-389f-49a3-b9ec-1254b0997c65)
</p>

## <p align="center">Anomalous DNS</p>
1. 
- zeek -r dns-tunneling.pcap
- ls
- cat dns.log | zeek-cut qtype_name | grep "AAAA" | uniq -c
- A - 320

 2. 
- zeek -r dns-tunneling.pcap
- cat conn.log | zeek-cut duration | sort -n | tail -1
- A - 9.420791

3.
- cat dns.log | less
- dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort | uniq
- A - 6

4.
- cat conn.log | less
- cat conn.log | zeek-cut id.orig_h id.resp_h | sort -n | uniq -c
- A - 10.20.57.3

## <p align="center">Phishing</p>
1.
- dhcp.log | less
- cat dhcp.log | zeek-cut client_addr | uniq | sed -e 's/\./[.]/g'
- A - 10[.]6[.]27[.]102
  
2.
- http.log | less
- cat http.log | zeek-cut host | grep "smart-fax" | uniq | sed -e 's/\./[.]/g'
- A - smart-fax[.]com
  
3.
- zeek -C -r phishing.pcap hash-demo.zeek
- cat files.log | zeek-cut mime_type md5 | grep "word"
- A - VBA
  
4. 
- cat files.log | zeek-cut mime_type md5 | grep "exe"
- A - PleaseWaitWindow.exe

5. 
- echo hopto.org | sed -e 's/\./[.]/g'
- A - hopto[.]org
  
6. 
- cat http.log | grep "exe"
- A - knr.exe

## <p align="center">Log4J</p>
1. 
- zeek -C -r log4shell.pcapng detection-log4j.zeek
- cat signatures.log | zeek-cut note | uniq -c
- A - 3

2. 
- cat http.log | zeek-cut user_agent | sort | uniq
- A - Nmap

3. 
- cat http.log | zeek-cut uri | sort | uniq
- A - .class

4. 
- cat log4j.log | zeek-cut uri | sort -nr | uniq
- A - pwned
