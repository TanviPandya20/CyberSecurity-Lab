# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/75b25c89-c2cd-48e4-bdbb-9282ff8b23ac)</p>

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

# <p align="center>"![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/322a9a95-8425-485f-91a8-b6b7db0bec7d)</p>

## <p align="center">CLI Kung-Fu Recall: Processing Zeek Logs</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/e467348c-c0fd-4167-a6aa-a057c588c07c)
</p>

# <p align="center"></p>

# <p align="center"></p>

## <p align="center">Zeek Signatures</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/f32d9e96-0f22-492c-b02f-2a02dda0986d)
</p>

## <p align="center">Zeek Scripts | Fundamentals</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/7f5d8060-1be1-4789-ae57-eb1798e1e19d)
</p>

## <p align="center">Zeek Scripts | Scripts and Signatures</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/c36a0246-c45b-4f17-912c-54d259dfcae7)
</p>

## <p align="center">Zeek Scripts | Frameworks</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/c7ad21cb-6caf-44dd-bac9-b9208f1436f2)
</p>

## <p align="center">Zeek Scripts | Packages</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/b2ff8024-4669-43a1-849d-7355a669f707)
</p>

# <p align="center">ZEEK Exercises</p>

# <p align="center">![image](https://github.com/TanviPandya20/CyberSecurity-Lab/assets/67452535/faffe67b-389f-49a3-b9ec-1254b0997c65)
</p>

## <p align="center">Anomalous DNS</p>
## <p align="center">Phishing</p>
## <p align="center">Log4J</p>

